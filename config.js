
/**
 * User Profile
 */
var profile = {
  userName: 'vikas.yadav@walkingtree.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  FirstName: 'Vikas',
  LastName: 'Yadav',
  displayName: 'Vikas Yadav',
  email: 'vikas.yadav@walkingtree.com',
  mobilePhone: '+916386000265',
  groups: 'Simple IdP Users, West Coast Users, Cloud Users'
}

/**
 * SAML Attribute Metadata
 */
var metadata = [{
  id: "FirstName",
  optional: false,
  displayName: 'First Name',
  description: 'The given name of the user',
  multiValue: false
}, {
  id: "LastName",
  optional: false,
  displayName: 'Last Name',
  description: 'The surname of the user',
  multiValue: false
}, {
  id: "displayName",
  optional: true,
  displayName: 'Display Name',
  description: 'The display name of the user',
  multiValue: false
}, {
  id: "email",
  optional: false,
  displayName: 'E-Mail Address',
  description: 'The e-mail address of the user',
  multiValue: false
},{
  id: "mobilePhone",
  optional: true,
  displayName: 'Mobile Phone',
  description: 'The mobile phone of the user',
  multiValue: false
}, {
  id: "groups",
  optional: true,
  displayName: 'Groups',
  description: 'Group memberships of the user',
  multiValue: true
}, {
  id: "userType",
  optional: true,
  displayName: 'User Type',
  description: 'The type of user',
  options: ['Admin', 'Editor', 'Commenter']
}];

module.exports = {
  user: profile,
  metadata: metadata
}
