import express from "express";
import { config } from "dotenv";
import { mongoose } from "mongoose";
import { UserModel } from "./models/user.js";
import jwt from "jsonwebtoken";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import { WebSocketServer } from "ws";
import { MessageModel } from "./models/Message.js";
import fs from "fs";
import path from "node:path";

config();

mongoose.connect(process.env.MONGODB_URL);

const app = express();
app.use(cors({ credentials: true, origin: "http://localhost:5173" }));
// const __dirname = path.dirname(new URL(import.meta.url).pathname);
app.use("/uploads", express.static("./uploads"));
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET));

const getUserDataFromRequest = async (req) => {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, {}, (err, userData) => {
        if (err) throw err;
        resolve(userData);
      });
    } else {
      reject("No Token");
    }
  });
};

app.get("/test", (req, res) => {
  res.json("test Ok");
});

app.get("/profile", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, {}, (err, userData) => {
      if (err) throw err;
      res.json({
        message: "Authenticated",
        userData,
      });
    });
  } else {
    res.status(401).json("NO Token Found");
  }
});

app.get("/people", async (req, res) => {
  try {
    const users = await UserModel.find({}, { _id: 1, username: 1 });
    res.status(200).json({ message: "OK", users });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: "ERROR", cause: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await UserModel.findOne({ username: username });
    if (!user) {
      res.status(404).json({ message: "Not Found" });
    }
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      res.status(403).json({ message: "Username or Password incorrect" });
    }
    const payload = { userID: user._id, username };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {});
    res
      .cookie("token", token)
      .status(201)
      .json({ message: "OK", id: user._id });
  } catch (err) {
    console.log(err);
    res.status(500).json("Something went wrong", err.message);
  }
});

app.post("/logout", async (req, res) => {
  try {
    res.clearCookie("token").status(200).json({ message: "OK" });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: "ERROR", cause: error.message });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = new UserModel({
      username,
      password: hashPassword,
    });
    await newUser.save();
    const payload = { userID: newUser._id, username };
    const token = jwt.sign(payload, process.env.JWT_SECRET);
    res
      .cookie("token", token)
      .status(201)
      .json({ message: "OK", id: newUser._id });
  } catch (error) {
    if (error) throw error;
    res.status(500).json("ERROR");
  }
});

app.get("/messages/:userID", async (req, res) => {
  try {
    const { userID } = req.params;
    const userData = await getUserDataFromRequest(req);
    const ourUserID = await userData.userID;
    const messages = await MessageModel.find({
      sender: { $in: [userID, ourUserID] },
      recipient: { $in: [userID, ourUserID] },
    })
      .sort({ createdAt: 1 })
      .exec();
    res.json({ message: "OK", messages });
  } catch (error) {
    console.log(error.message);
    res.json({
      message: "No User ID found to be delivered",
      cause: error.message,
    });
  }
});

const server = app.listen(4000, () => {
  console.log("The server is up and running");
});

const wss = new WebSocketServer({ server });

// Read username and id from the cookie for this connection
wss.on("connection", (connection, req) => {
  console.log("Connected to Web Sockets Server!");

  const notifyAboutOnlinePeople = () => {
    [...wss.clients].forEach((client) => {
      client.send(
        JSON.stringify({
          online: [...wss.clients].map((c) => ({
            userID: c.userID,
            username: c.username,
          })),
        })
      );
    });
  };

  connection.isAlive = true;

  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
      // console.log("dead");
    }, 1000);
  }, 5000);

  connection.on("pong", () => {
    clearTimeout(connection.deathTimer);
  });

  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies
      .split(";")
      .find((str) => str.startsWith("token="));
    if (tokenCookieString) {
      const token = tokenCookieString.split("=")[1];
      if (token) {
        jwt.verify(token, process.env.JWT_SECRET, {}, (err, userData) => {
          if (err) throw err;
          const { userID, username } = userData;
          connection.userID = userID;
          connection.username = username;
        });
      }
    }
  }

  connection.on("message", async (message) => {
    const messageData = JSON.parse(message.toString());
    const { recipient, text, file } = messageData;
    let fileName = null;
    if (file) {
      const parts = file.name.split(".");
      const ext = parts[parts.length - 1];
      fileName = Date.now() + "." + ext;
      const path = "./uploads/" + fileName;
      const bufferData = new Buffer(file.data.split(",")[1], "base64");
      fs.writeFile(path, bufferData, () => {
        console.log("File Saved: " + path);
      });
    }

    if (recipient && (text || file)) {
      const newMessage = new MessageModel({
        sender: connection.userID,
        recipient,
        text,
        file: file ? fileName : null,
      });
      await newMessage.save();
      console.log("created message");
      [...wss.clients]
        .filter((c) => c.userID === recipient)
        .forEach((c) =>
          c.send(
            JSON.stringify({
              text,
              sender: connection.userID,
              recipient,
              file: file ? fileName : null,
              _id: newMessage._id,
            })
          )
        );
    }
  });

  // Notify everyone about people online (when someone connects)
  notifyAboutOnlinePeople();

  // console.log([...wss.clients].map((c) => c.username));
});

wss.on("close", (data) => {
  console.log("Disconnected", data);
});

// jWk6t4NL9AZNDccs
// vershivu
