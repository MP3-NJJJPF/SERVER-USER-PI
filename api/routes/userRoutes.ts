import express from "express";
import UserController from "../controlllers/UserController";
//import User from "../models/User";
import loginLimiter from "../middlewares/limiterMiddleware";
import authenticateToken from "../middlewares/authMiddleware";
import { authenticateFirebase } from "../middlewares/authenticateFirebase";
const router = express.Router();

/**
 * @route POST /users
 * @description Create a new user.
 * @body {string} first name - The name of the user.
 * @body {string} last name - The last name of the user.
 * @body {number} age - The age of the user.
 * @body {string} email - The mail of the user.
 * @body {string} password - The password of the user.
 * @body {string} confirmPassword - The password of the user to confirm.
 * @returns 201 with the id of the created user.
 * @access Public
 */
router.post("/", (req, res) => UserController.create(req, res));


/**
 * @route POST /users/login
 * @description Login.
 * @body {string} email - The mail of the user.
 * @body {string} password - The password of the user.
 * @returns 200 with a success message and a cookie that contains the token inside it.
 * @access Public
 */
router.post("/login", loginLimiter, (req, res) => UserController.login(req, res));

/**
 * @route POST /users/logout
 * @description Logout.
 * @returns 200 with a success message.
 * @access Public
 */
router.post("/logout", (req, res) => UserController.logout(req, res));

/**
 * @route POST /users/forgot-password
 * @description Send an email to recover the password.
 * @body {string} email - The mail of the user (It has to be real, or simulated by some website).
 * @returns 200 with a success message and an email with a recovery link containing the token.
 * @access Public
 */
router.post("/forgot-password", (req, res) => UserController.forgotPassword(req, res));

/**
 * @route POST /users/reset-password
 * @description change the password.
 * @body {string} password - The new password of the user.
 * @body {string} confirmPassword - The new password of the user to confirm.
 * @body {string} token - The token that was sent via email (in the link).
 * @body {string} email - The mail of the user that was sent via email (in the link).
 * @returns 200 with a success message.
 * @access Public
 */
router.post("/reset-password", (req, res) => UserController.resetPassword(req, res));

/**
 * @route GET /users
 * @description Retrieve all users.
 * @access Public
 */
router.get("/", (req, res) => UserController.getAll(req, res));

/**
 * @route PUT /users/edit-me
 * @description Edit the logged-in user's details.
 * @body {string} [firstName] - Updated first name (optional).
 * @body {string} [lastName] - Updated last name (optional).
 * @body {number} [age] - Updated age (optional).
 * @body {string} [email] - Updated email (optional).
 * @returns 200 with the updated user's details.
 * @access Public
 */

router.put('/edit-me', authenticateToken, (req, res) => UserController.editLoggedUser(req, res));

/**
 * @route DELETE /me
 * @description Elimina la cuenta del usuario autenticado después de validar su identidad.
 * @access Private (requiere autenticación con JWT)
 * @middleware authenticateToken - Middleware que valida el token y añade los datos del usuario a `req.user`.
 * @body {string} password - Contraseña actual del usuario para confirmar la eliminación de la cuenta.
 * @returns {object} 200 - Cuenta eliminada exitosamente.
 * @returns {object} 400 - Si faltan datos obligatorios.
 * @returns {object} 401 - Si la contraseña es incorrecta o el token no es válido.
 * @returns {object} 404 - Si el usuario no existe.
 */

router.delete("/me", authenticateToken, (req, res) => UserController.deleteLoggedUser(req, res));

/**
 * @route PATCH /change-password
 * @description Updates (changes) the authenticated user's password after verifying their identity.
 * @access Private (requires JWT authentication)
 * @middleware authenticateToken - Middleware that validates the JWT token and attaches user data to `req.user`.
 * 
 * @body {string} currentPassword - The user's current password (required for verification).
 * @body {string} password - The new password to be set.
 * @body {string} confirmPassword - Confirmation of the new password (must match `password`).
 * 
 * @returns {object} 200 - Password successfully changed.
 * @returns {object} 400 - Missing or invalid input fields.
 * @returns {object} 401 - Invalid token or incorrect current password.
 * @returns {object} 404 - User not found.
 * @returns {object} 500 - Unexpected server error.
 */
router.patch('/change-password', authenticateToken, (req, res) => UserController.changePassword(req, res));

/**
 * @route GET /users/me
 * @description Get the logged-in user's details.
 * @returns 200 with the user's details.
 * @access Public
 */

router.get('/me', authenticateToken, (req, res) => UserController.getLoggedUser(req, res));

/**
 * @route GET /check-token
 * @description Verifica que el token JWT enviado sea válido.
 * @access Private (requiere autenticación con JWT)
 * @middleware authenticateToken - Middleware que valida el token y añade los datos del usuario a `req.user`.
 * @returns {object} 200 - Devuelve un mensaje confirmando que el token es válido.
 */

router.get("/check-token", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Token valido" });
});

/**
 * @route POST /google
 * @description Manages the Google OAuth login flow. If the user exists in the database, 
 * logs them in using a JWT cookie. If the user does not exist, returns an incomplete profile status to complete the registration.
 * @access Private (requires Firebase Authentication)
 * @middleware authenticateFirebase - Middleware that verifies Firebase ID token and attaches decoded user data to `req.user`
 * @returns {object} 200 - Login successful with JWT cookie set
 * @returns {object} 200 - incomplete_profile status if user needs to complete registration
 * @example
 * // Request headers
 * Authorization: Bearer <firebase_id_token>
 * 
 * // Success response (existing user)
 * {
 *   "message": "Login successful with google",
 * }
 * 
 * // Response (new user needs registration)
 * {
 *   "status": "incomplete_profile",
 * }
 */
router.post("/google", authenticateFirebase, (req, res) => UserController.googleLogin(req, res));

/**
 * @route POST /complete-profile
 * @description Completes Google OAuth registration for new users. Creates user account with additional 
 * profile information after Firebase authentication. Automatically logs in user with JWT cookie.
 * @access Private (requires Firebase Authentication)
 * @middleware authenticateFirebase - Middleware that verifies Firebase ID token and attaches decoded user data to `req.user`
 * @body {string} email - User's email address (from Google)
 * @body {string} password - User's chosen password
 * @body {string} confirmPassword - Password confirmation (must match password)
 * @body {string} firstName - User's first name
 * @body {string} lastName - User's last name
 * @body {number} age - User's age
 * @returns {object} 201 - User registered successfully with JWT cookie set
 * @returns {object} 400 - Password validation error
 * @returns {object} 409 - Email already in use
 * @returns {object} 500 - Internal server error
 * @example
 * // Request headers
 * Authorization: Bearer <firebase_id_token>
 */
router.post("/complete-profile", authenticateFirebase, (req, res) => UserController.googleRegister(req, res));


/**
 * Export the router instance to be mounted in the main routes file.
 */
export default router;