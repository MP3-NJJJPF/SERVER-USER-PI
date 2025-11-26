import express from "express";
import MeetingController from "../controllers/MeetingController";

const router = express.Router();

/**
 * POST /create
 *
 * Creates a new meeting with a unique ID in the format "xxx-yyy-zzz".
 * Generates a formatted meeting ID, initializes default meeting properties,
 * and stores the meeting in Firestore.
 * Uses MeetingController.createMeeting() to handle the request.
 *
 * @route POST /create
 * @param {express.Request} req - Incoming HTTP request with optional hostId in body
 * @param {express.Response} res - HTTP response containing the generated meetingId
 * @returns {Object} 201 - Success response with meetingId
 * @returns {Object} 500 - Error response if meeting creation fails
 */
router.post("/create", (req, res) => MeetingController.createMeeting(req, res));

/**
 * GET /:id
 *
 * Retrieves detailed information about a specific meeting by its ID.
 * Returns meeting data including hostId, participants, status, and other properties.
 * Uses MeetingController.getMeeting() to handle the request.
 *
 * @route GET /:id
 * @param {express.Request} req - Incoming HTTP request with meeting ID in URL params
 * @param {express.Response} res - HTTP response containing meeting data
 * @returns {Object} 200 - Success response with meeting object
 * @returns {Object} 404 - Error response if meeting not found
 * @returns {Object} 500 - Error response if retrieval fails
 */
router.get("/:id", (req, res) => MeetingController.getMeeting(req, res));

/**
 * POST /add-participant
 *
 * Adds a new participant to a meeting or reconnects an existing participant.
 * If the participant already exists in the meeting, marks them as connected.
 * If the participant is new, adds them to the participants array with initial data.
 * Uses MeetingController.joinMeeting() to handle the request.
 *
 * @route POST /add-participant
 * @param {express.Request} req - Incoming HTTP request with meetingId, userId, and optional name in body
 * @param {express.Response} res - HTTP response confirming participant connection
 * @returns {Object} 200 - Success response confirming participant connected
 * @returns {Object} 500 - Error response if connection fails
 */
router.post("/add-participant", (req, res) => MeetingController.joinMeeting(req, res));

/**
 * POST /remove-participant
 *
 * Removes a participant from a meeting by marking them as disconnected.
 * Does not delete the participant from the meeting's participants array,
 * only updates their isConnected status to false.
 * Uses MeetingController.leaveMeeting() to handle the request.
 *
 * @route POST /remove-participant
 * @param {express.Request} req - Incoming HTTP request with meetingId and userId in body
 * @param {express.Response} res - HTTP response confirming participant disconnection
 * @returns {Object} 200 - Success response confirming participant disconnected
 * @returns {Object} 500 - Error response if disconnection fails
 */
router.post("/remove-participant", (req, res) => MeetingController.leaveMeeting(req, res));

/**
 * Exports the router instance so it can be mounted
 * in the application's main routing file.
 * All routes defined here will be prefixed with the base path
 * specified when mounting this router (e.g., "/api/meetings").
 *
 * @module MeetingRoutes
 */
export default router;