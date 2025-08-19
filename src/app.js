import express, { urlencoded } from "express";
import cors from "cors";
const app = express();

//  app.use() -> middleware

// basic config
app.use(express.json({ limit: "16kb" })); // body parser to accpt json data
app.use(urlencoded({ extended: true }, { limit: "16kb" })); // to accept urlencoded data
app.use(express.static("public")); // to enable serving static files from public folder

//cors cnfig

app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:3000", // what url i will allowed to communicate with backend
    credentials: true, // to accept cookies
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// import the routes
import heathCheckRouter from "./routes/heathcheck.routes.js";
import authRouter from "./routes/auth.routes.js";

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/healthcheck", heathCheckRouter);

app.get("/", (req, res) => {
  res.send("welcome to projectCamp");
});

app.get("/instagram", (req, res) => {
  res.send("this is an instagram page");
});

export default app;
