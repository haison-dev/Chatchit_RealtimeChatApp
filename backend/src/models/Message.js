import mongoose from "mongoose";
import { CALL_KINDS, CALL_STATUSES } from "../utils/callOutcome.js";

// Set only on the record a finished 1-1 call leaves in the conversation.
const callSchema = new mongoose.Schema({
  kind: { type: String, enum: CALL_KINDS, required: true },
  status: { type: String, enum: CALL_STATUSES, required: true },
  duration: { type: Number, min: 0, default: 0 }, // seconds the call was connected
}, { _id: false });

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
    call: { type: callSchema, default: undefined },
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
