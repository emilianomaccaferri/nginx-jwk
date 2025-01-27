import express from "express";
import {
  exportJWK,
  generateKeyPair,
  SignJWT
} from 'jose';
const app = express();
const { publicKey, privateKey } = await generateKeyPair('ES512', {
  extractable: true,
  crv: "P-521"
});
const exportedPublicKey = await exportJWK(publicKey);

app.get('/jwk', async (req, res) => {
  res.json({ keys: [exportedPublicKey] });
});

app.get('/example-token', async (req, res) => {
  const token = await new SignJWT({ 'example-claim': 'hello :)))' })
    .setProtectedHeader({ alg: 'ES512' })
    .setIssuedAt()
    .setExpirationTime('24h')
    .sign(privateKey);
  res.json({
    token
  })
})

app.listen(3000)
console.log("listening")
