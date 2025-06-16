/**
 * Module dependencies.
 */

const chalk               = require('chalk'),
      express             = require('express'),
      os                  = require('os'),
      fs                  = require('fs'),
      http                = require('http'),
      https               = require('https'),
      path                = require('path'),
      extend              = require('extend'),
      hbs                 = require('hbs'),
      logger              = require('morgan'),
      bodyParser          = require('body-parser'),
      session             = require('express-session'),
      yargs               = require('yargs/yargs'),
      xmlFormat           = require('xml-formatter'),
      samlp               = require('samlp'),
      Parser              = require('@xmldom/xmldom').DOMParser,
      SessionParticipants = require('samlp/lib/sessionParticipants'),
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
  'cert',
  'key',
  'encryptionCert',
  'encryptionPublicKey',
  'httpsPrivateKey',
  'httpsCert',
];
const WILDCARD_ADDRESSES = ['0.0.0.0', '::'];
const UNDEFINED_VALUE = 'None';

function matchesCertType(value, type) {
  const CRYPT_TYPES = {
    certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
    'RSA private key': /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
    'public key': /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
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
  if (str.length == 0) return hash;
  for (let i = 0; i < str.length; i++) {
    let char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash;
}

function formatOptionValue(key, value) {
  if (typeof value === 'string') return value;
  if (CERT_OPTIONS.includes(key)) {
    return value.toString().replace(/-----.+?-----|\n/g, '').substring(0, 80) + '…';
  }
  if (!value && value !== false) return UNDEFINED_VALUE;
  if (typeof value === 'function') return `${value}`.split('\n')[0].slice(0, -2);
  return `${JSON.stringify(value)}`;
}

function prettyPrintXml(xml, indent) {
  const prettyXml = xmlFormat(xml, { indentation: '  ' })
    .replace(/<(\/)?((?:[\w]+)(?::))?([\w]+)(.*?)>/g, `<$1$2$3$4>`)
    .replace(/ ([\w:]+)="(.+?)"/g, ` $1="$2"`);
  if (indent) return prettyXml.replace(/(^|\n)/g, `$1${' '.repeat(indent)}`);
  return prettyXml;
}

function processArgs(args, options) {
  var baseArgv = options ? yargs(args).config(options) : yargs(args);
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
      disableRequestAcsUrl: { boolean: true, alias: 'static', default: false },
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
      signResponse: { boolean: true, default: true, alias: 'signResponse' },
      configFile: { default: 'saml-idp/config.js', alias: 'conf' },
      rollSession: { boolean: true, default: false },
      authnContextClassRef: {
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        alias: 'acr'
      },
      authnContextDecl: {
        string: true,
        alias: 'acd',
        coerce: function (value) {
          const filePath = resolveFilePath(value);
          if (filePath) return fs.readFileSync(filePath, 'utf8');
        }
      }
    })
    .check(function(argv) {
      if (argv.encryptAssertion) {
        if (argv.encryptionPublicKey === undefined) return 'encryptionPublicKey argument is required for assertion encryption';
        if (argv.encryptionCert === undefined) return 'encryptionCert argument is required for assertion encryption';
      }
      return true;
    })
    .check(function(argv) {
      if (argv.config) return true;
      const configFilePath = resolveFilePath(argv.configFile);
      if (!configFilePath) return 'SAML attribute config file path "' + argv.configFile + '" is not a valid path.\n';
      try {
        argv.config = require(configFilePath);
      } catch (error) {
        return 'Exception while loading SAML attribute config file "' + configFilePath + '".\n' + error;
      }
      return true;
    });
}

function _runServer(argv) {
  const app = express();
  const httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);
  const blocks = {};

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
    getPostURL: (audience, authnRequestDom, req, callback) => {
      return callback(null, (req.authnRequest && req.authnRequest.acsUrl) ? req.authnRequest.acsUrl : req.idp.options.acsUrl);
    },
    transformAssertion: function(assertionDom) {
      if (argv.authnContextDecl) {
        let declDoc;
        try {
          declDoc = new Parser().parseFromString(argv.authnContextDecl);
        } catch (err) {}
        if (declDoc) {
          const authnContextDeclEl = assertionDom.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDecl');
          authnContextDeclEl.appendChild(declDoc.documentElement);
          const authnContextEl = assertionDom.getElementsByTagName('saml:AuthnContext')[0];
          authnContextEl.appendChild(authnContextDeclEl);
        }
      }
    },
    responseHandler: function(response, opts, req, res, next) {
      res.render('samlresponse', {
        AcsUrl: opts.postUrl,
        SAMLResponse: response.toString('base64'),
        RelayState: opts.RelayState
      });
    }
  };

  app.set('host', process.env.HOST || argv.host);
  app.set('port', process.env.PORT || argv.port);
  app.set('views', path.join(__dirname, 'views'));
  app.set('view engine', 'hbs');
  app.set('view options', { layout: 'layout' });
  app.engine('handlebars', hbs.__express);

  hbs.registerHelper('extend', function(name, context) {
    var block = blocks[name];
    if (!block) block = blocks[name] = [];
    block.push(context.fn(this));
  });
  hbs.registerHelper('block', function(name) {
    const val = (blocks[name] || []).join('\n');
    blocks[name] = [];
    return val;
  });
  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value="' + selected + '"'), '$& selected="selected"');
  });
  hbs.registerHelper('getProperty', function(attribute, context) {
    return context[attribute];
  });
  hbs.registerHelper('serialize', function(context) {
    return Buffer.from(JSON.stringify(context)).toString('base64');
  });

  app.use(logger('dev'));
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    secret: 'The universe works on a math equation that never even ever really ends in the end',
    resave: false,
    saveUninitialized: true,
    name: 'idp_sid',
    cookie: { maxAge: 60 * 60 * 1000 }
  }));

  const showUser = function(req, res, next) {
    res.render('user', {
      user: req.user,
      participant: req.participant,
      metadata: req.metadata,
      authnRequest: req.authnRequest,
      idp: req.idp.options,
      paths: IDP_PATHS
    });
  };

  const parseSamlRequest = function(req, res, next) {
    samlp.parseRequest(req, function(err, data) {
      if (err) {
        return res.render('error', {
          message: 'SAML AuthnRequest Parse Error: ' + err.message,
          error: err
        });
      }
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
      return showUser(req, res, next);
    });
  };

  const getSessionIndex = function(req) {
    if (req && req.session) {
      return Math.abs(getHashCode(req.session.id)).toString();
    }
  };

  const getParticipant = function(req) {
    return {
      serviceProviderId: req.idp.options.serviceProviderId,
      sessionIndex: getSessionIndex(req),
      nameId: req.user.userName,
      nameIdFormat: req.user.nameIdFormat,
      serviceProviderLogoutURL: req.idp.options.sloUrl
    };
  };

  const parseLogoutRequest = function(req, res, next) {
    if (!req.idp.options.sloUrl) {
      return res.render('error', {
        message: 'SAML Single Logout Service URL not defined for Service Provider'
      });
    }
    return samlp.logout({
      issuer: req.idp.options.issuer,
      cert: req.idp.options.cert,
      key: req.idp.options.key,
      digestAlgorithm: req.idp.options.digestAlgorithm,
      signatureAlgorithm: req.idp.options.signatureAlgorithm,
      sessionParticipants: new SessionParticipants([req.participant]),
      clearIdPSession: function(callback) {
        req.session.destroy();
        callback();
      }
    })(req, res, next);
  };

  app.use(function(req, res, next) {
    if (argv.rollSession) {
      req.session.regenerate(function() {
        return next();
      });
    } else {
      next();
    }
  });

  app.use(function(req, res, next) {
    req.user = argv.config.user;
    req.metadata = argv.config.metadata;
    req.idp = { options: idpOptions };
    req.participant = getParticipant(req);
    next();
  });

  app.get(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);
  app.post(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);

  app.get(IDP_PATHS.SLO, parseLogoutRequest);
  app.post(IDP_PATHS.SLO, parseLogoutRequest);

  app.post(IDP_PATHS.SIGN_IN, function(req, res) {
    const authOptions = extend({}, req.idp.options);
    Object.keys(req.body).forEach(function(key) {
      if (key === '_authnRequest') {
        const buffer = Buffer.from(req.body[key], 'base64');
        req.authnRequest = JSON.parse(buffer.toString('utf8'));
        authOptions.inResponseTo = req.authnRequest.id;
        if (req.idp.options.allowRequestAcsUrl && req.authnRequest.acsUrl) {
          authOptions.acsUrl = req.authnRequest.acsUrl;
          authOptions.recipient = req.authnRequest.acsUrl;
          authOptions.destination = req.authnRequest.acsUrl;
          authOptions.forceAuthn = req.authnRequest.forceAuthn;
        }
        if (req.authnRequest.relayState) {
          authOptions.RelayState = req.authnRequest.relayState;
        }
      } else {
        req.user[key] = req.body[key];
      }
    });

    if (!authOptions.encryptAssertion) {
      delete authOptions.encryptionCert;
      delete authOptions.encryptionPublicKey;
    }
    authOptions.sessionIndex = getSessionIndex(req);
    samlp.auth(authOptions)(req, res);
  });

  app.get(IDP_PATHS.METADATA, function(req, res) {
    samlp.metadata(req.idp.options)(req, res);
  });

  app.post(IDP_PATHS.METADATA, function(req, res) {
    if (req.body && req.body.attributeName && req.body.displayName) {
      let attributeExists = false;
      const attribute = {
        id: req.body.attributeName,
        optional: true,
        displayName: req.body.displayName,
        description: req.body.description || '',
        multiValue: req.body.valueType === 'multi'
      };
      req.metadata.forEach(function(entry) {
        if (entry.id === req.body.attributeName) {
          entry = attribute;
          attributeExists = true;
        }
      });
      if (!attributeExists) req.metadata.push(attribute);
      res.status(200).end();
    }
  });

  app.get(IDP_PATHS.SIGN_OUT, function(req, res) {
    if (req.idp.options.sloUrl) {
      res.redirect(IDP_PATHS.SLO);
    } else {
      req.session.destroy(function(err) {
        if (err) throw err;
        res.redirect('back');
      });
    }
  });

  app.get([IDP_PATHS.SETTINGS], function(req, res) {
    res.render('settings', { idp: req.idp.options });
  });

  app.post([IDP_PATHS.SETTINGS], function(req, res) {
    Object.keys(req.body).forEach(function(key) {
      switch (req.body[key].toLowerCase()) {
        case "true": case "yes": case "1":
          req.idp.options[key] = true;
          break;
        case "false": case "no": case "0":
          req.idp.options[key] = false;
          break;
        default:
          req.idp.options[key] = req.body[key];
          break;
      }
      if (req.body[key].match(/^\d+$/)) {
        req.idp.options[key] = parseInt(req.body[key], 10);
      }
    });
    res.redirect('/');
  });

  app.use(function(req, res, next) {
    const err = new Error('Route Not Found');
    err.status = 404;
    next(err);
  });

  app.use(function(err, req, res, next) {
    if (err) {
      res.status(err.status || 500);
      res.render('error', {
        message: err.message,
        error: err
      });
    }
  });

  httpServer.listen(app.get('port'), app.get('host'));
  return httpServer;
}

function runServer(options) {
  const args = processArgs([], options);
  return _runServer(args.argv);
}

function main() {
  const args = processArgs(process.argv.slice(2));
  _runServer(args.argv);
}

module.exports = {
  runServer,
  main,
};

if (require.main === module) {
  main();
}
