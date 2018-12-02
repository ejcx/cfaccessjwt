# cfaccessjwt
Verify Cloudflare Access JWTs quickly and easily.

# Installing
```
yarn add cfaccessjwt
```

# Example
```
var cfaccessjwt = require('cfaccessjwt');

const accessDomain = 'https://ejjio.cloudflareaccess.com';
const aud = '9d4a635bdcc097213b4474263bb494515713df90575b6efc0ec7ace78e0a30cb';

async function verify(jwt) {
  var jwkBlob = await fetch(accessDomain + '/cdn-cgi/access/certs')
  var jwks = await jwkBlob.json()
  var auth = await cfaccessjwt(jwks, jwt, aud, accessDomain)
  return auth
}
```