import UserDAO from "../dao/userDAO";
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import { IUserCreate } from "../models/User";

sgMail.setApiKey(process.env.SENDGRID_API_KEY as string);

/**
 * UserController
 *
 * Handles user-specific logic such as registration, login, and password validation for the Taskly backend.
 *
 * @class UserController
*/
class UserController {
  /**
   * Creates a new user with validation and password hashing.
   * Checks for password match, email uniqueness, and hashes the password before saving.
   *
   * @async
   * @override
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Promise<void>}
  */
  async create(req: Request, res: Response): Promise<void> {
    try {
      // Take user data from request body
      const { email, password, confirmPassword, firstName, lastName, age } = req.body;

      // Validate password and confirmPassword match
      const passwordError = this.passwordValidation(req);
      if (passwordError) {
        res.status(400).json({ message: passwordError });
        return;
      }

      // Check if the email already exists
      const existingUser = await UserDAO.getUserByEmail(req.body.email);
      if (existingUser) {
        res.status(409).json({ message: "Correo electrónico ya en uso" });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user in Firestore database
      const newUser: IUserCreate = {
        firstName,
        lastName,
        age,
        email,
        password: hashedPassword,
        role: "user",
        isActive: true,
      };

      const userId = await UserDAO.create(newUser);
      res.status(201).json({ message: "Usuario registrado correctamente.", id: userId });
    } catch (error: any) {
      // Show detailed error only in development
      if (process.env.NODE_ENV === "development") {
        console.error(error);
      }
      res.status(500).json({ message: "Internal Server Error" });
    }
  }

  // Additional validation for password
  /**
   * Validates the password and confirmPassword fields in the request.
   * Ensures they match and meet complexity requirements.
   *
   * @param {Object} req - Express request object
   * @returns {string|null} Error message if invalid, otherwise null
  */
  passwordValidation(req: Request): string | null {
    if (req.body.password != req.body.confirmPassword) {
      return "La contraseña y la confirmación de contraseña no coinciden";
    }

    // Remove confirmPassword before saving
    delete req.body.confirmPassword;

    // Validate the password syntaxis
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/
    if (!passwordRegex.test(req.body.password)) {
      return "La contraseña no es válida";
    }

    return null;
  }

  /**
    * Authenticates a user by email and password.
    * Checks credentials and returns a success message and user ID if valid.
    *
    * @async
    * @param {Object} req - Express request object
    * @param {Object} res - Express response object
    * @returns {Promise<number|void>} Returns 0 on success, otherwise sends error response
    */
  async login(req: Request, res: Response): Promise<void> {
    try {
      // Check if the email exists and take the user
      const user = await UserDAO.getUserByEmail(req.body.email);
      if (!user) {
        res.status(401).json({ message: "Correo electrónico o contraseña inválidos" });
        return;
      }

      // Compare the provided password with the stored hashed password
      const passwordMatch = await bcrypt.compare(req.body.password, user.password as string);
      if (!passwordMatch) {
        res.status(401).json({ message: "Correo electrónico o contraseña inválidos" });
        return;
      }

      // Define secure type to process.env.JWT_SECRET
      const jwtSecret = process.env.JWT_SECRET as string;
      if (!jwtSecret) {
        throw new Error("JWT_SECRET no está definido en las variables de entorno");
      }

      // Generate a JWT token, with the structure: sign(payload (data), secret (to sign), options)
      const token = jwt.sign(
        {
          userId: user.uid
        },
        jwtSecret,
        { expiresIn: '2h' }
      );

      // Define secure type to process.env.JWT_SECRET
      const COOKIE_CONTROL = process.env.COOKIE_CONTROL as string;
      if (!COOKIE_CONTROL) {
        throw new Error("COOKIE_CONTROL no está definido en las variables de entorno");
      }

      // Send the token in a HTTP-only cookie
      res.cookie('token', token,
        {
          httpOnly: true, // JavaScript cannot access this cookie for the side of the client
          secure: process.env.NODE_ENV === 'production', // Only be sent via HTTPS
          sameSite: COOKIE_CONTROL as "none" | "lax" | "strict", // Allows cross-origin cookies; reduces CSRF protection. Use only if cross-site requests are required.
          maxAge: 2 * 60 * 60 * 1000 // 2 hours in milliseconds
        }
      );

      // Successful login
      res.status(200).json({ message: "Login successful", id: user.uid, email: user.email, name: user.firstName, age: user.age });
    } catch (error: any) {
      // Show detailed error only in development
      if (process.env.NODE_ENV === "development") {
        console.error(error);
      }
      res.status(500).json({ message: "Internal Server Error" });
    }
  }

  /**
    * Logout method to clear the JWT token cookie.
    * Clears the authentication cookie (`token`) using the same options
    * as when it was created, effectively logging out the user.
    * 
    * @function logout
    * @param {import("express").Request} req - Express request object.
    * @param {import("express").Response} res - Express response object.
    * @returns {void} Sends a 200 response with a success message.
    */
  logout(req: Request, res: Response): void {
    // Define secure type to process.env.JWT_SECRET
    const COOKIE_CONTROL = process.env.COOKIE_CONTROL as string;
    if (!COOKIE_CONTROL) {
      throw new Error("COOKIE_CONTROL no está definido en las variables de entorno");
    }
    // Clear the token cookie with the same options used to create it
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: COOKIE_CONTROL as "none" | "lax" | "strict",
    });
    res.status(200).json({ message: "Logged out successfully" });
  }

  /**
  * Sends a password reset email to the user.
  *
  * - Verifies if the provided email exists.
  * - Generates a JWT reset token valid for 1 hour.
  * - Stores the token and expiration date in the user record.
  * - Sends an email with the reset link to the user.
  *
  * @async
  * @function forgotPassword
  * @param {import("express").Request} req - Express request object. Expects `req.body.email`.
  * @param {import("express").Response} res - Express response object.
  * @returns {Promise<void>} Sends a 200 response if the email is sent,
  * 202 if the email does not exist, or 500 on server error.
  */
  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      // Check if the email exists and take the user
      const user = await UserDAO.getUserByEmail(req.body.email);
      if (!user) {
        res.status(202).json({ message: "If the email is registered, you will receive a password reset email" });
        return
      }

      // Define secure type to process.env.JWT_SECRET
      const jwtSecret = process.env.JWT_SECRET as string;
      if (!jwtSecret) {
        throw new Error("JWT_SECRET no está definido en las variables de entorno");
      }

      // Generate a JWT token, with the structure: sing(payload (data), secret (to sign), options)
      const token = jwt.sign(
        {
          userId: user.uid,
        },
        jwtSecret,
        { expiresIn: '1h' }
      );

      // Save the token and its expiration date in the instance of the user
      user.resetPasswordToken = token;
      user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour from now

      // Update the user with the reset token and expiration
      await UserDAO.update(user.uid as string, user);

      // The URL is constructed, the user must open to reset their password. 
      // The user's token and email are included as query parameters.
      const origins = process.env.ORIGIN?.split(",").map(url => url.trim()).filter(Boolean);
      if (!origins || origins.length === 0) {
        throw new Error("No se encontró ninguna URL válida en la variable ORIGIN");
      }
      const baseUrl = origins[1] as string; // Use the first valid origin (Change in production for 1)
      const resetUrl = `${baseUrl}/reset-password?token=${token}&email=${user.email}`;

      // 5) Configure the email content
      const msg: sgMail.MailDataRequired = {
        to: user.email,
        from: process.env.EMAIL_USER as string, // verified sender in SendGrid
        subject: "Recuperar contraseña - TalkHub",
        html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <p>Hemos recibido una solicitud para restablecer tu contraseña en <strong>TalkHub</strong>.</p>
          <p>Haz clic en el siguiente botón para continuar:</p>
          <p>
            <a href="${resetUrl}" 
            style="display: inline-block; padding: 10px 20px; background: #007BFF; 
                  color: #fff; text-decoration: none; border-radius: 5px;">
            Restablecer contraseña
            </a>
          </p>
          <p>Si no solicitaste este cambio, simplemente ignora este correo.</p>
          <hr/>
          <small>Este enlace expirará en 1 hora por razones de seguridad.</small>
        </div>
      `,
      };

      // 6) Send email with SendGrid
      await sgMail.send(msg);
      console.log(" Correo enviado exitosamente a:", user.email);
      res.status(200).json({ message: "Password reset email sent" });

    } catch (error: any) {
      console.error("Forgot password error:", error.message || error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  }

  /**
   * Resets the user's password using the reset token.
  *
  * - Validates the token and email combination.
  * - Ensures password and confirmPassword match.
  * - Hashes and updates the new password in the database.
  * - Clears the reset token and expiration fields.
  *
  * @async
  * @function resetPassword
  * @param {import("express").Request} req - Express request object. 
  * Expects `req.body.email`, `req.body.token`, `req.body.password`, and `req.body.confirmPassword`.
  * @param {import("express").Response} res - Express response object.
  * @returns {Promise<void>} Sends a 200 response if reset is successful,
  * 400 if the token is invalid/expired, or 500 on server error.
  */
  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      // Find the user with the reset token and the email
      const user = await UserDAO.readByResetToken(req.body.email, req.body.token);
      console.log("User found for password reset:", user);
      if (!user) {
        res.status(400).json({ message: "Token inválido o expirado" });
        return;
      }

      // Validate password and confirmPassword match
      const passwordError = this.passwordValidation(req);
      if (passwordError) {
        res.status(400).json({ message: passwordError });
        return
      }

      // Hash the new password before saving it
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      user.password = hashedPassword;

      // Delete the token and expiration date
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;


      // Update the user in the database
      await UserDAO.update(user.uid as string, user);


      res.status(200).json({ message: "Password has been reset successfully" });

    } catch (error: any) {
      // Show detailed error only in development
      if (process.env.NODE_ENV === "development") {
        console.error(error);
      }
      res.status(500).json({ message: "Inténtalo de nuevo más tarde" });
    }
  }

  /**
      * Retrieves all resources, optionally filtered by query parameters.
      * @async
      * @param {Object} req - Express request object
      * @param {Object} res - Express response object
      * @returns {void}
    */
  async getAll(req: Request, res: Response): Promise<void> {
    try {
      const items = await UserDAO.getAll();
      res.status(200).json(items);
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }

    /** Edits the information of the currently authenticated user.
       * Allows updating fields like firstName, lastName, age, and email.
       * Requires a valid JWT token for authentication.
       * @param {Object} req - Express request object.
       * @param {Object} res - Express response object.
       * @returns {Promise<void>} Sends a response indicating success or an error message.
       */
    async editLoggedUser(req: Request, res: Response): Promise<void> {
      try {
        const authReq = req as Request & { userId?: string };
        const userId = authReq.userId;

        if (!userId) {
          res.status(401).json({ message: "No token provided" });
          return;
        }

        const user = await UserDAO.getById(userId);

        if (!user) {
          res.status(404).json({ message: "User not found" });
          return;
        }

        const allowedFields = ["firstName", "lastName", "age", "email"];
        const updates = Object.fromEntries(
          allowedFields
            .filter(field => req.body[field] !== undefined)
            .map(field => [field, req.body[field]])
        );


        Object.assign(user, updates);
        

        // usar el userId del token en vez de user.uid ya que biene como undefined
        await UserDAO.update(userId, user); 

        res.status(200).json({ message: "User information updated successfully" });

      } catch (error: any) {
        res.status(500).json({ message: error.message || "Error updating user information" });
      }
  }

  /**
    * Deletes the currently authenticated user after verifying their password.
    *
    * @async
    * @function deleteLoggedUser
    * @memberof UserController
    * @description
    * - Validates the JWT token from the request to identify the user.
    * - Verifies the provided password matches the user's stored password.
    * - Deletes all tasks associated with the user.
    * - Deletes the user account from the database.
    * - Clears the authentication cookie.
    *
    * @param {import('express').Request} req - Express request object.
    * @param {import('express').Response} res - Express response object.
    *
    * @body {string} password - The current password of the user to confirm account deletion.
    *
    * @returns {Promise<void>}
    * @throws {401} If no token is provided or if the password is incorrect.
    * @throws {404} If the user is not found.
    * @throws {500} If an unexpected server error occurs.
    */
  async deleteLoggedUser(req: Request, res: Response): Promise<void> {
    try {
      const authReq = req as Request & { userId?: string }; // Extend the request type to include userId
      const userId = authReq.userId;

      if (!userId) {
        res.status(401).json({ message: "No token provided" });
        return;
      }

      const user = await UserDAO.getById(userId);
      if (!user) {
        res.status(404).json({ message: "Usuario no encontrado" });
        return;
      }

      const passwordMatch = await bcrypt.compare(req.body.password, user.password as string);
      if (!passwordMatch) {
        res.status(401).json({ message: "Contraseña incorrecta" });
        return;
      }

      //await TaskDAO.deleteByUserId(user._id);
      await UserDAO.delete(user.uid as string);

      // Define secure type to process.env.JWT_SECRET
      const COOKIE_CONTROL = process.env.COOKIE_CONTROL as string;
      if (!COOKIE_CONTROL) {
        throw new Error("COOKIE_CONTROL no está definido en las variables de entorno");
      }

      res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: COOKIE_CONTROL as "none" | "lax" | "strict",
      });

      res.status(200).json({ message: "Usuario eliminado" });

    } catch (error: any) {
      console.error(error);
      res.status(500).json({ message: "Error al eliminar el usuario" });
    }
  }

  /**
     * Changes the password of the currently authenticated user.
     *
     * @async
     * @function changePassword
     * @memberof UserController
     * @description
     * - Validates the JWT token from the request to identify the user.
     * - Verifies the current password matches the user's stored password.
     * - Validates the new password meets security requirements.
     * - Hashes and updates the new password in the database.
     *
     * @param {import('express').Request} req - Express request object.
     * @param {import('express').Response} res - Express response object.
     *
     * @body {string} currentPassword - The user's current password for verification.
     * @body {string} password - The new password to set.
     * @body {string} confirmPassword - Confirmation of the new password.
     *
     * @returns {Promise<void>}
     * @throws {401} If no token is provided or if the current password is incorrect.
     * @throws {404} If the user is not found.
     * @throws {400} If password validation fails.
     * @throws {500} If an unexpected server error occurs.
     */
  async changePassword(req: Request, res: Response): Promise<void> {
    try {
      const authReq = req as Request & { userId?: string };
      const userId = authReq.userId;

      if (!userId) {
        res.status(401).json({ message: "No se proporcionó un token" });
        return;
      }

      const user = await UserDAO.getById(userId);
      if (!user) {
        res.status(404).json({ message: "Usuario no encontrado" });
        return;
      }

      // Verify current password
      const passwordMatch = await bcrypt.compare(req.body.currentPassword, user.password as string);
      if (!passwordMatch) {
        res.status(401).json({ message: "La contraseña actual es incorrecta" });
        return;
      }

      // Validate new password and confirmPassword match
      const passwordError = this.passwordValidation(req);
      if (passwordError) {
        res.status(400).json({ message: passwordError });
        return;
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      user.password = hashedPassword;

      // Update the user in the database
      await UserDAO.update(userId as string, user);

      res.status(200).json({ message: "Contraseña cambiada exitosamente" });

    } catch (error: any) {
      // Show detailed error only in development
      if (process.env.NODE_ENV === "development") {
        console.error(error);
      }
      res.status(500).json({ message: "Error al cambiar la contraseña" });
    }
  }

  /**
    * Gets the information of the currently authenticated user.
    *
    * - Validates the JWT token from the request to identify the user.
    * @param {Object} req - Express request object.
    * @param {Object} res - Express response object.
    */
  async getLoggedUser(req: Request, res: Response): Promise<void> {
    try {
      const authReq = req as Request & { userId?: string };
      const userId = authReq.userId;

      if (!userId) {
        res.status(401).json({ message: "No se proporcionó un token" });
        return;
      }

      const user = await UserDAO.getById(userId);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      res.status(200).json({
        user: {
          id: user.uid,
          firstName: user.firstName,
          lastName: user.lastName,
          age: user.age,
          email: user.email,
          role: user.role,
          isActive: user.isActive,
        }
      });
    } catch (error: any) {
      console.error(error);
      res.status(500).json({ message: "Error getting user information" });
    }
  }

  /**
  * Manage the Google OAuth login flow for existing users or flag an incomplete profile for new users.
  * 
  * This method performs the following steps:
  * 1. Extracts Firebase user information from the authenticated request
  * 2. Checks if a user with the given email exists in the database
  * 3. If user doesn't exist, returns incomplete_profile status for registration completion
  * 4. If user exists, generates a JWT token and sets it as an HTTP-only cookie
  * 
  * @async
  * @param {Request} req - Express request object containing Firebase authenticated user data
  * @param {Response} res - Express response object used to send the login result
  * @returns {Promise<void>} Resolves when the response has been sent
  */
  async googleLogin(req: Request, res: Response): Promise<void> {
    try {
      const firebaseUser = (req as any).user;
      const { email, name, uid } = firebaseUser;

      // 1) Search if the email exists and take the user
      const user = await UserDAO.getUserByEmail(email);

      // 2) If user does not exist, respond with incomplete_profile status
      if (!user) {
        res.json({
          status: "incomplete_profile",
          email: email,
          userid: uid
        });
        return;
      }

      // 3) If user exists, log them in (create JWT and send cookie)

      // Define secure type to process.env.JWT_SECRET
      const jwtSecret = process.env.JWT_SECRET as string;
      if (!jwtSecret) {
        throw new Error("JWT_SECRET no está definido en las variables de entorno");
      }

      // Generate a JWT token, with the structure: sign(payload (data), secret (to sign), options)
      const token = jwt.sign(
        {
          userId: user.uid
        },
        jwtSecret,
        { expiresIn: '2h' }
      );

      // Define secure type to process.env.JWT_SECRET
      const COOKIE_CONTROL = process.env.COOKIE_CONTROL as string;
      if (!COOKIE_CONTROL) {
        throw new Error("COOKIE_CONTROL no está definido en las variables de entorno");
      }

      // Send the token in a HTTP-only cookie
      res.cookie('token', token,
        {
          httpOnly: true, // JavaScript cannot access this cookie for the side of the client
          secure: process.env.NODE_ENV === 'production', // Only be sent via HTTPS
          sameSite: COOKIE_CONTROL as "none" | "lax" | "strict", // Allows cross-origin cookies; reduces CSRF protection. Use only if cross-site requests are required.
          maxAge: 2 * 60 * 60 * 1000 // 2 hours in milliseconds
        }
      );

      // Successful login
      res.status(200).json({ message: "Login successful with google", id: user.uid, email: user.email });

    } catch (error: any) {
      // Show detailed error only in development
      if (process.env.NODE_ENV === "development") {
        console.error(error);
      }
      res.status(500).json({ message: "Internal Server Error" });
    }
  }

  /**
  * Manage user registration via Google OAuth with additional profile information and apply a login.
  * 
  * This method performs the following steps:
  * 1. Validates that passwords match using passwordValidation helper
  * 2. Checks if the email is already registered in the database
  * 3. Hashes the password using bcrypt
  * 4. Creates a new user record in Firestore
  * 5. Generates a JWT token and sets it as an HTTP-only cookie
  * 6. Returns success response with the new user ID
  * 
  * @async
  * @param {Request} req - Express request object containing user registration data in body
  * @param {Request} req.body.email - User's email address
  * @param {Request} req.body.password - User's chosen password
  * @param {Request} req.body.confirmPassword - Password confirmation for validation
  * @param {Request} req.body.firstName - User's first name
  * @param {Request} req.body.lastName - User's last name
  * @param {Request} req.body.age - User's age
  * @param {Response} res - Express response object used to send the registration result
  * @returns {Promise<void>} Resolves when the response has been sent
  * 
  * @throws {Error} If JWT_SECRET environment variable is not defined
  * @throws {Error} If COOKIE_CONTROL environment variable is not defined
  */
  async googleRegister(req: Request, res: Response): Promise<void> {
    try {
      const firebaseUser = (req as any).user;
      const { email, name, uid } = firebaseUser;

      // Take user data from request body
      const { age } = req.body;
      
      // Validate required fields
      if (!age) {
        res.status(400).json({ error: "La edad es requerida" });
        return;
      }

      if (!firebaseUser || !firebaseUser.email) {
        res.status(400).json({ error: "Datos de Firebase inválidos" });
        return;
      }

      // Normalize email
      const normalizedEmail = email.trim().toLowerCase();

      // Check if the email already exists
      const existingUser = await UserDAO.getUserByEmail(normalizedEmail);
      if (existingUser) {
        res.status(409).json({ message: "Correo electrónico ya en uso" });
        return;
      }

      // Extract name from Firebase (handle cases where name might be empty)
      const fullName = name || email.split("@")[0];
      const nameParts = fullName.split(" ");
      const firstName = nameParts[0] || "Usuario";
      const lastName = nameParts.slice(1).join(" ") || "Google";

      // Generate a random password
      const randomPassword = Math.random().toString(36).slice(-16) + Math.random().toString(36).slice(-16);
      const salt = bcrypt.genSaltSync(10);
      const hashedPassword = bcrypt.hashSync(randomPassword, salt);

      // Create user in Firestore database
      const newUser: IUserCreate = {
        firstName,
        lastName,
        age,
        email: normalizedEmail,
        password: hashedPassword,
        role: "user",
        isActive: true,
      };

      // Save the new user to Firestore and get the generated user ID
      const userId = await UserDAO.create(newUser);

      // Retrieve the newly created user to verify creation
      const user = await UserDAO.getById(userId);
      if (!user) {
        res.status(401).json({ message: "Id no válido" });
        return;
      }

      // Define secure type to process.env.JWT_SECRET
      const jwtSecret = process.env.JWT_SECRET as string;
      if (!jwtSecret) {
        throw new Error("JWT_SECRET no está definido en las variables de entorno");
      }

      // Generate a JWT token, with the structure: sign(payload (data), secret (to sign), options)
      const token = jwt.sign(
        {
          userId: user.uid
        },
        jwtSecret,
        { expiresIn: '2h' }
      );

      // Define secure type to process.env.JWT_SECRET
      const COOKIE_CONTROL = process.env.COOKIE_CONTROL as string;
      if (!COOKIE_CONTROL) {
        throw new Error("COOKIE_CONTROL no está definido en las variables de entorno");
      }

      // Send the token in a HTTP-only cookie
      res.cookie('token', token,
        {
          httpOnly: true, // JavaScript cannot access this cookie for the side of the client
          secure: process.env.NODE_ENV === 'production', // Only be sent via HTTPS
          sameSite: COOKIE_CONTROL as "none" | "lax" | "strict", // Allows cross-origin cookies; reduces CSRF protection. Use only if cross-site requests are required.
          maxAge: 2 * 60 * 60 * 1000 // 2 hours in milliseconds
        }
      );

      res.status(201).json({ message: "Usuario registrado correctamente.", id: userId });
    } catch (error: any) {
      // Show detailed error only in development
      if (process.env.NODE_ENV === "development") {
        console.error(error);
      }
      res.status(500).json({ message: "Internal Server Error" });
    }
  }
}

export default new UserController();
