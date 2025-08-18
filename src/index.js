import dotenv from "dotenv";
import app from "./app.js";
dotenv.config({
  path: "./.env",
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Example app listening on http://localhost:${port}`);
});
console.log("start of backend project changes");
