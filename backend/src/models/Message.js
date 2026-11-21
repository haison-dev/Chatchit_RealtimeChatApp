import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Conversation",
      required: true,
      index: true,
    },
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    clientMessageId: {
      type: String,
      trim: true,
      maxlength: 100,
    },
    content: { type: String, trim: true },
    imgUrl: { type: String },
    editedAt: { type: Date, default: null },
    deletedAt: { type: Date, default: null },
    reactions: [{
      _id: false,
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
      emoji: { type: String, required: true, maxlength: 16 },
    }],
  },
  { timestamps: true }
);

messageSchema.index({ conversationId: 1, createdAt: -1 });
messageSchema.index({ conversationId: 1, content: 1 });
// getImage looks up the message that owns an image on every non-uploader view.
messageSchema.index({ imgUrl: 1 }, { partialFilterExpression: { imgUrl: { $type: "string" } } });
messageSchema.index(
  { senderId: 1, clientMessageId: 1 },
  { unique: true, partialFilterExpression: { clientMessageId: { $type: "string" } } },
);


const Message = mongoose.model("Message", messageSchema);
export default Message;
