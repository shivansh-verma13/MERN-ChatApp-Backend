import mongoose from "mongoose";

const MessageSchema = new mongoose.Schema(
  {
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    text: String,
    file: String,
  },
  { timestamps: true }
);

export const MessageModel = mongoose.model("message", MessageSchema);
