const encoder = new TextEncoder();
const decode = (encoded) => {
  encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  return decodeBase64(encoded);
}
const decodeBase64 = (encoded) => {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};
const validateJwt = async (res) => {
  try {
    // get the jwk (which can be cached)
    const jwk = await res.subrequest('/kc/realms/master/protocol/openid-connect/certs');
    const parsed_jwk = JSON.parse(jwk.responseText);
    const preferred_key = parsed_jwk["keys"]
      .filter(k =>
        k.use === "sig"
        && k.alg === "RS256" // "ES512"
      );

    if (preferred_key.length === 0)
      throw new Error('no preferred key');

    const jwt = res.variables.header_token;
    const key = await crypto
      .subtle
      .importKey(
        "jwk",
        preferred_key[0],
        {
          /*name: "ECDSA",
          namedCurve: "P-521"*/
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256"
        },
        true,
        ["verify"]
      );
    const jwt_split = jwt.split(".");
    if (jwt_split.length !== 3) {
      res.variables.no_auth_reason = "invalid_jwt";
      res.return(401);
      return;
    }
    const decoded_header = atob(jwt_split[0]);
    const signing_input = jwt_split.slice(0, 2).join('.');
    const verify = await crypto.subtle.verify({
      name: "RSASSA-PKCS1-v1_5",
      // namedCurve: "P-521",
      hash: "SHA-256",// from the header
    },
      key,
      decode(jwt_split[2]),
      encoder.encode(signing_input),
    );
    res.error(verify);
    if (!verify) {
      res.variables.no_auth_reason = "bad_signature";
      res.return(401);
      return;
    }
    res.return(203);
  } catch (err) {
    res.error(err);
    res.variables.no_auth_reason = "generic_error";
    res.return(401);
  }
}

export default {
  validateJwt
}
