import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    // The field name is kept for database compatibility; only a SHA-256 hash is stored.
    refreshToken: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },
    // Hash of the token that was just replaced. It stays valid for a few seconds so
    // parallel refresh calls (several tabs, page reload) do not log the user out.
    previousRefreshToken: { type: String, index: true, sparse: true },
    rotatedAt: { type: Date },
  },
  {
    timestamps: true,
  }
);

//auto remove after expiresAt
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model("Session", sessionSchema);
