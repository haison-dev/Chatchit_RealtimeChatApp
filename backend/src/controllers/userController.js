import User from '../models/User.js';


export const authMe = async (req, res) => {
    try {
        const user = req.user; //get from authMiddleware

        return res.status(200).json({ user });
    } catch (error) {
        console.error('Error when calling authMe.', error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const searchUserByUsername = async (req, res) =>{
    try {
        const { username } = req.query;
        if(!username || username.trim() === '') {
            res.status(400).json({ message: "Username query parameter is required." });
        }

        const user = await User.findOne({username}).select('_id displayName username avatarUrl');

        res.status(200).json({ user }); 
    } catch (error) {
        console.error('Error when calling searchUserByUsername.', error);
        return res.status(500).json({ message: "Internal server error" });
    }
}