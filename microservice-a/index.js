const express = require("express");
const app = express();

app.get('/', async (req, res) => {
  const result = await fetch('http://nginx:8000/b/', {
    headers: {
      ...req.headers,
    }
  });
  const json = await result.json();
  return res.json(json);
})

app.listen(3000);
console.log("listening");
