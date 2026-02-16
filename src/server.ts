import app from "./app.js";

const PORT = process.env.PORT || 8788;

app.listen(PORT, () => {
  console.log(`Solace Adapter listening on ${PORT}`);
});
