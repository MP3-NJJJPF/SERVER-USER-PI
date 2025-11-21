import express from "express";
import MeetingController from "../controllers/MeetingController";

const router = express.Router();

/**
 * POST /create
 *
 * Creates a new meeting with a unique ID.
 * Uses MeetingController.createMeeting() to handle the request.
 *
 * @route POST /create
 * @param {express.Request} req - Incoming HTTP request
 * @param {express.Response} res - HTTP response sent to client
 */
router.post("/create", (req, res) => MeetingController.createMeeting(req, res));

/**
 * GET /
 *
 * Returns information about a meeting.
 * Uses MeetingController.getMeeting() to handle the request.
 *
 * @route GET /
 * @param {express.Request} req - Incoming HTTP request
 * @param {express.Response} res - HTTP response sent to client
 */
router.get("/", (req, res) => MeetingController.getMeeting(req, res));

/**
 * Exports the router instance so it can be mounted
 * in the application's main routing file.
 *
 * @module MeetingRoutes
 */
export default router;