const passwords = require('./passwords');

const db = {
  dan: passwords.saltHashPassword('hello')
};

const hello = async (event) => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'I\'m authenticated!',
      input: event,
    }),
  };
};

const postExample = async (event) => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'I\'m authenticated too!',
      input: event,
    }),
  };
};

const generatePolicy = ({principalId = 'user', effect = 'Allow', resources = "*"}) => {
  const authResponse = {
    principalId
  };

  authResponse.policyDocument = {
    Version: '2012-10-17', // default version
    Statement: [
      {
        Action: 'execute-api:Invoke', // default action
        Effect: effect,
        Resource: resources
      }
    ]
  };

  return authResponse;
};

const auth = async event => {
  const { authorizationToken, methodArn } = event;
  const matchedArn = methodArn.match(/[^\/]+/);
  const genericArn = matchedArn[0] + '/*';
  const lambdasToApprove = [genericArn];

  const deny = () => generatePolicy({
    effect: 'Deny',
    resources: lambdasToApprove
  });

  if (!authorizationToken) {
    return deny();
  }

  const [type, token] = authorizationToken.split(" ");

  if (type !== 'Basic') {
    return deny();
  }

  const credentials = passwords.getCredentialsFromAuthToken(token);

  console.log("DB");
  console.log(db);
  console.log("credentials");
  console.log(credentials);

  const storedPassword = db[credentials.username];

  console.log("storedPassword");
  console.log(storedPassword);

  if (!storedPassword) {
    return deny();
  }

  if (!passwords.validatePassword(credentials.password, storedPassword.passwordHash, storedPassword.salt)) {
    return deny();
  }

  console.log("password validated");

  const response = generatePolicy({
    resources: lambdasToApprove
  });

  // this must be a flat object for some reason
  response.context = {
    role: 'client',
    app: JSON.stringify({
      appId: 'dummy app'
    })
  };

  console.log(JSON.stringify(response));

  return response;
};

module.exports = {
  hello,
  postExample,
  auth
};
