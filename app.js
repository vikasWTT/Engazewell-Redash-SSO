/**
 * Module dependencies.
 */
const chalk = require('chalk'),
      express = require('express'),
      fs = require('fs'),
      http = require('http'),
      https = require('https'),
      path = require('path'),
      extend = require('extend'),
      logger = require('morgan'),
      bodyParser = require('body-parser'),
      session = require('express-session'),
      yargs = require('yargs/yargs'),
      samlp = require('samlp'),
      Parser = require('@xmldom/xmldom').DOMParser,
      SimpleProfileMapper = require('./lib/simpleProfileMapper.js');

/**
 * Globals
 */
const IDP_PATHS = {
  SSO: '/saml/sso',
  SLO: '/saml/slo',
  METADATA: '/metadata',
  SIGN_IN: '/signin',
  SIGN_OUT: '/signout',
  SETTINGS: '/settings'
};
const CERT_OPTIONS = [
  'cert', 'key', 'encryptionCert', 'encryptionPublicKey',
  'httpsPrivateKey', 'httpsCert'
];

function matchesCertType(value, type) {
  const CRYPT_TYPES = {
    certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
    'RSA private key': /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
    'public key': /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/
  };
  return CRYPT_TYPES[type] && CRYPT_TYPES[type].test(value);
}

function resolveFilePath(filePath) {
  if (filePath.startsWith('saml-idp/')) {
    const resolvedPath = require.resolve(filePath.replace(/^saml\-idp\//, `${__dirname}/`));
    return fs.existsSync(resolvedPath) && resolvedPath;
  }
  if (fs.existsSync(filePath)) return filePath;
  if (filePath.startsWith('~/')) {
    const possiblePath = path.resolve(process.env.HOME, filePath.slice(2));
    if (fs.existsSync(possiblePath)) return possiblePath;
    return filePath;
  }
  return ['.', __dirname]
    .map(base => path.resolve(base, filePath))
    .find(possiblePath => fs.existsSync(possiblePath));
}

function makeCertFileCoercer(type, description) {
  return function certFileCoercer(value) {
    if (matchesCertType(value, type)) return value;
    const filePath = resolveFilePath(value);
    if (filePath) return fs.readFileSync(filePath);
    throw new Error(`Invalid / missing ${description} - not a valid crypt key/cert or file path`);
  };
}

function getHashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    let char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash;
}

function processArgs(args, options) {
  const baseArgv = options ? yargs(args).config(options) : yargs(args);
  return baseArgv
    .options({
      host: { default: 'localhost' },
      port: { alias: 'p', default: 7000 },
      cert: {
        default: './idp-public-cert.pem',
        coerce: makeCertFileCoercer('certificate', 'IdP Signature PublicKey Certificate')
      },
      key: {
        default: './idp-private-key.pem',
        coerce: makeCertFileCoercer('RSA private key', 'IdP Signature PrivateKey Certificate')
      },
      issuer: { alias: 'iss', default: 'urn:example:idp' },
      acsUrl: { alias: 'acs' },
      sloUrl: { alias: 'slo' },
      audience: { alias: 'aud' },
      serviceProviderId: { alias: 'spId', string: true },
      relayState: { alias: 'rs' },
      disableRequestAcsUrl: { boolean: true, default: false },
      encryptAssertion: { boolean: true, alias: 'enc', default: false },
      encryptionCert: {
        string: true,
        alias: 'encCert',
        coerce: makeCertFileCoercer('certificate', 'Encryption cert')
      },
      encryptionPublicKey: {
        string: true,
        alias: 'encKey',
        coerce: makeCertFileCoercer('public key', 'Encryption public key')
      },
      httpsPrivateKey: {
        string: true,
        coerce: makeCertFileCoercer('RSA private key')
      },
      httpsCert: {
        string: true,
        coerce: makeCertFileCoercer('certificate')
      },
      https: { boolean: true, default: false },
      signResponse: { boolean: true, default: true },
      configFile: { default: 'saml-idp/config.js', alias: 'conf' },
      rollSession: { boolean: true, default: false },
      authnContextClassRef: {
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      },
      authnContextDecl: {
        string: true,
        coerce: function (value) {
          const filePath = resolveFilePath(value);
          if (filePath) return fs.readFileSync(filePath, 'utf8');
        }
      },
      showUserInfoPage: { boolean: false, default: false }
    })
    .check(argv => {
      if (argv.encryptAssertion) {
        if (!argv.encryptionPublicKey) return 'encryptionPublicKey is required';
        if (!argv.encryptionCert) return 'encryptionCert is required';
      }
      const configFilePath = resolveFilePath(argv.configFile);
      if (!configFilePath) return `Invalid config path: ${argv.configFile}`;
      try {
        argv.config = require(configFilePath);
      } catch (e) {
        return `Failed to load config: ${e}`;
      }
      return true;
    });
}

function _runServer(argv) {
  const app = express();
  const server = argv.https
    ? https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app)
    : http.createServer(app);

  const idpOptions = {
    issuer: argv.issuer,
    serviceProviderId: argv.serviceProviderId || argv.audience,
    cert: argv.cert,
    key: argv.key,
    audience: argv.audience,
    recipient: argv.acsUrl,
    destination: argv.acsUrl,
    acsUrl: argv.acsUrl,
    sloUrl: argv.sloUrl,
    RelayState: argv.relayState,
    allowRequestAcsUrl: !argv.disableRequestAcsUrl,
    digestAlgorithm: 'sha256',
    signatureAlgorithm: 'rsa-sha256',
    signResponse: argv.signResponse,
    encryptAssertion: argv.encryptAssertion,
    encryptionCert: argv.encryptionCert,
    encryptionPublicKey: argv.encryptionPublicKey,
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    lifetimeInSeconds: 3600,
    authnContextClassRef: argv.authnContextClassRef,
    authnContextDecl: argv.authnContextDecl,
    includeAttributeNameFormat: true,
    profileMapper: SimpleProfileMapper.fromMetadata(argv.config.metadata),
    postEndpointPath: IDP_PATHS.SSO,
    redirectEndpointPath: IDP_PATHS.SSO,
    logoutEndpointPaths: argv.sloUrl ? { redirect: IDP_PATHS.SLO, post: IDP_PATHS.SLO } : {},
    getUserFromRequest: req => req.user,
    getPostURL: (audience, authnRequestDom, req, cb) =>
      cb(null, req.authnRequest?.acsUrl || req.idp.options.acsUrl),
    transformAssertion: assertionDom => {
      if (argv.authnContextDecl) {
        try {
          const declDoc = new Parser().parseFromString(argv.authnContextDecl);
          const authnContextEl = assertionDom.getElementsByTagName('saml:AuthnContext')[0];
          const declEl = assertionDom.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDecl');
          declEl.appendChild(declDoc.documentElement);
          authnContextEl.appendChild(declEl);
        } catch {}
      }
    }
  };

  app.set('host', argv.host);
  app.set('port', argv.port);

  app.use(logger('dev'));
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(session({
    secret: 'The universe works on a math equation that never ends',
    resave: false,
    saveUninitialized: true,
    name: 'idp_sid',
    cookie: { maxAge: 60 * 60 * 1000 }
  }));

  const getSessionIndex = req =>
    req?.session ? Math.abs(getHashCode(req.session.id)).toString() : undefined;

  const getParticipant = req => ({
    serviceProviderId: req.idp.options.serviceProviderId,
    sessionIndex: getSessionIndex(req),
    nameId: req.user.userName,
    nameIdFormat: req.user.nameIdFormat,
    serviceProviderLogoutURL: req.idp.options.sloUrl
  });

  app.use((req, res, next) => {
    if (argv.rollSession) req.session.regenerate(() => next());
    else next();
  });

  app.use((req, res, next) => {
    req.user = argv.config.user;
    req.metadata = argv.config.metadata;
    req.idp = { options: idpOptions };
    req.participant = getParticipant(req);
    next();
  });

  app.all(IDP_PATHS.SSO, (req, res) => {
    samlp.parseRequest(req, (err, data) => {
      if (err) return res.status(400).send('SAML AuthnRequest Parse Error: ' + err.message);

      if (data) {
        req.authnRequest = {
          relayState: req.query.RelayState || req.body.RelayState,
          id: data.id,
          issuer: data.issuer,
          destination: data.destination,
          acsUrl: data.assertionConsumerServiceURL,
          forceAuthn: data.forceAuthn === 'true'
        };
      }

      // Simulated login check
      let bengazewelluserlogin = true;
      if (!bengazewelluserlogin) {
        return res.status(401).send('User not authenticated. Please log in to Engazewell before accessing Redash.');
      }

      const authOptions = extend({}, req.idp.options, {
        sessionIndex: getSessionIndex(req),
        inResponseTo: req.authnRequest?.id,
        acsUrl: req.authnRequest?.acsUrl,
        recipient: req.authnRequest?.acsUrl,
        destination: req.authnRequest?.acsUrl,
        RelayState: req.authnRequest?.relayState
      });

      if (!authOptions.encryptAssertion) {
        delete authOptions.encryptionCert;
        delete authOptions.encryptionPublicKey;
      }

      return samlp.auth(authOptions)(req, res);
    });
  });

  app.get(IDP_PATHS.METADATA, (req, res) => {
    samlp.metadata(req.idp.options)(req, res);
  });

  app.use((req, res) => res.status(404).send('Route Not Found'));
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).send(`Error: ${err.message}`);
  });

  server.listen(app.get('port'), app.get('host'));
  return server;
}

function runServer(options) {
  const args = processArgs([], options);
  return _runServer(args.argv);
}

function main() {
  const args = processArgs(process.argv.slice(2));
  _runServer(args.argv);
}

module.exports = { runServer, main };

if (require.main === module) {
  main();
}
