import { auth } from "../config/firebase.config";
import GlobalDAO from "./GlobalDAO";
import { IUser, IUserCreate } from "../models/User";

class UserDAO extends GlobalDAO<IUser> {
  constructor() {
    super("users");
  }

  /**
   * Finds a user document by email address.
   * @async
   * @param emailToSearch - The email address to search for
   * @returns The found user document or null if not found
   */
  async getUserByEmail(email: string): Promise<IUser | null> {
    try {
      // Search for the user in Firebase Auth
      //const userRecord = await auth.getUserByEmail(email);

      // Search for the corresponding document in Firestore (optional)
      const snapshot = await this.collectionRef
        .where("email", "==", email)
        .limit(1)
        .get();

      if (snapshot.empty) {
        return null;
      }

      const data = snapshot.docs[0].data() as IUser;

      // Ensure UID exists (if not set, fallback to the document ID)
      if (!data.uid) {
        data.uid = snapshot.docs[0].id;
      }

      return data;
    } catch (error: any) {
      if (error.code === "auth/user-not-found") {
        return null;
      }
      throw error;
    }
  }

  /**
 * Finds a user document by email and reset token, ensuring token is not expired.
 * @async
 * @param email - The user's email
 * @param token - The reset token
 * @returns The found user document or null if not found or expired
 */
  /**
 * Finds a user document by email and reset token, ensuring token is not expired.
 * @async
 * @param email - The user's email
 * @param token - The reset token
 * @returns The found user document or null if not found or expired
 */
  async readByResetToken(email: string, token: string): Promise<IUser | null> {
    try {
      // Search for the user document with matching email and reset token
      const snapshot = await this.collectionRef
        .where("email", "==", email)
        .where("resetPasswordToken", "==", token)
        .limit(1)
        .get();

      if (snapshot.empty) {
        console.log(" No user found with given email and token");
        return null;
      }

      const userDoc = snapshot.docs[0];
      const data = userDoc.data() as IUser;

      // Verify that the token is not expired
      if (data.resetPasswordExpires) {
        // Convert Firestore Timestamp to Date if necessary
        const expiresDate =
          data.resetPasswordExpires instanceof Date
            ? data.resetPasswordExpires
            : (data.resetPasswordExpires as any).toDate();

        if (expiresDate.getTime() < Date.now()) {
          console.warn(` Reset token expired for user: ${email}`);
          return null;
        }
      } else {
        console.warn(` No expiration date set for token of user: ${email}`);
        return null;
      }

      // If the user does not have a UID, assign the document ID
      if (!data.uid) {
        data.uid = userDoc.id;
      }

      return data;
    } catch (error: any) {
      console.error(" Error reading user by reset token:", error);
      throw new Error(`Error fetching user by reset token: ${error.message}`);
    }
  }

}

export default new UserDAO();