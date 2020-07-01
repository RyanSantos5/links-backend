const {verifyJwt, getTokenFromHeaders} = require('../helpers/jwt');

const checkJwt = (req, res, next) => {
  // /auth/sign-in
  // /auth/sign-up
  // /auth/admin
  // const adminsPaths = ['/auth/admin'];
  const {url: path} = req;

  const excludedPaths = ['/auth/sign-in','/auth/sign-up','/auth/refresh'];
  const isExcluded = !!excludedPaths.find(p => p.startsWith(path));

  console.log(path , isExcluded);
  
  if(isExcluded) return next();

  //Pegando o Refresh token
  const token = getTokenFromHeaders(req.headers);
  if(!token) {
    return res.jsonUnathorized(null, 'Invalid token');
  }
  
  // Verificando  se o token é valido e concede acesso
  try {
    const decoded = verifyJwt(token);
    req.accountId = decoded.id;
    next();
  } catch (error) {
    return res.jsonUnathorized(null, 'Invalid token');
  }
};

module.exports = checkJwt;