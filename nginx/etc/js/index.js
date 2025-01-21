const validateJwt = async (res) => {
  try {
    // get the jwk (which can be cached)
    const jwk = await res.subrequest('/kc/realms/master/protocol/openid-connect/certs');
    const parsed_jwk = JSON.parse(jwk.responseText);
    const preferred_key = parsed_jwk["keys"]
      .filter(k =>
        k.use === "sig"
        && k.alg === "RS256"
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
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["encrypt"]
      );
    const jwt_split = jwt.split(".");
    if (jwt.split.length !== 3) {
      res.variables.no_auth_reason = "invalid_jwt";
      res.return(401);
      return;
    }
    const [header, payload, signature] = jwt_split;
    const verify = await crypto.subtle.verify({
      name: "RSA-OAEP",
    },
      key,
      signature,
      data
    );
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
