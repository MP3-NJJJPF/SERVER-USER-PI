import { Request, Response } from "express";
import { nanoid } from "nanoid";
import MeetingDAO from "../dao/MeetingDAO";
import { IMeeting } from "../models/Meetings";

/**
 * MeetingController - Handles HTTP requests related to meeting operations.
 * Provides endpoints for creating, retrieving, joining, and leaving meetings.
 */
export class MeetingController {

  /**
   * Creates a new meeting with a formatted ID.
   * Generates a unique meeting ID in the format "xxx-yyy-zzz" and stores it in the database.
   * 
   * @param {Request} req - Express request object containing hostId in the body
   * @param {Response} res - Express response object
   * @returns {Promise<void>}
   */
  async createMeeting(req: Request, res: Response): Promise<void> {
    try {
      // Generate a 9-character random ID using nanoid
      const rawId = nanoid(9);
      // Format the ID into "xxx-yyy-zzz" pattern by splitting every 3 characters
      const meetingId =
        rawId.match(/.{1,3}/g)?.join("-") || rawId;

      // Build the meeting object with default values
      const meeting: IMeeting = {
        meetingId,
        hostId: req.body.hostId || null,
        isActive: true,
        maxParticipants: 10,
        participants: [],
      };

      // Save the meeting to Firestore using the DAO
      // Note: Alternative approach would be to manually set the document ID
      // await MeetingDAO.collectionRef.doc(meetingId).set({
      //   ...meeting,
      //   createdAt: new Date(),
      //   updatedAt: new Date(),
      // });

      await MeetingDAO.create(meeting);

      // Send success response with the generated meeting ID
      res.status(201).json({
        ok: true,
        meetingId,
        message: "Meeting created successfully",
      });
      return;

    } catch (error) {
      // Log the error and send error response
      console.error("Error creating meeting:", error);
      res.status(500).json({
        ok: false,
        error: "An error occurred while creating the meeting",
      });
      return;
    }
  }

  /**
   * Retrieves meeting information by meeting ID.
   * Fetches a single meeting's details from the database.
   * 
   * @param {Request} req - Express request object containing meeting ID in params
   * @param {Response} res - Express response object
   * @returns {Promise<void>}
   */
  async getMeeting(req: Request, res: Response): Promise<void> {
    try {
      // Extract the meeting ID from the URL parameters
      const { id } = req.params;

      // Query the database for the meeting
      const meeting = await MeetingDAO.getMeetingById(id);

      // If meeting doesn't exist, return 404 error
      if (!meeting) {
        res.status(404).json({
          ok: false,
          message: "Meeting not found",
        });
        return
      }

      // Send the meeting data in the response
      res.json({
        ok: true,
        meeting,
      });
      return;

    } catch (error) {
      // Log the error and send error response
      console.error("Error getting meeting:", error);
      res.status(500).json({
        ok: false,
        error: "Failed to fetch meeting",
      });
      return
    }
  }

  /**
   * Adds a participant to a meeting or reconnects an existing participant.
   * Updates the meeting's participant list with the user's information.
   * 
   * @param {Request} req - Express request object containing meetingId, userId, and optional name in body
   * @param {Response} res - Express response object
   * @returns {Promise<void>}
   */
  async joinMeeting(req: Request, res: Response): Promise<void> {
    try {
      // Extract participant details from request body
      const { meetingId, userId, name } = req.body;

      // Connect the participant to the meeting (adds new or reconnects existing)
      await MeetingDAO.connectParticipant(meetingId, userId, name);

      // Send success response
      res.status(200).json({ ok: true, message: "Participant connected" });
    } catch (error) {
      // Log the error and send error response
      console.error("Error connecting participant:", error);
      res.status(500).json({ ok: false, error: "Failed to connect participant" });
    }
  }

  /**
   * Removes a participant from a meeting.
   * Marks the participant as disconnected without removing them from the meeting.
   * 
   * @param {Request} req - Express request object containing meetingId and userId in body
   * @param {Response} res - Express response object
   * @returns {Promise<void>}
   */
  async leaveMeeting(req: Request, res: Response): Promise<void> {
    try {
      // Extract meeting ID and user ID from request body
      const { meetingId, userId } = req.body;

      // Disconnect the participant from the meeting
      await MeetingDAO.disconnectParticipant(meetingId, userId);

      // Send success response
      res.status(200).json({ ok: true, message: "Participant disconnected" });
    } catch (error) {
      // Log the error and send error response
      console.error("Error disconnecting participant:", error);
      res.status(500).json({ ok: false, error: "Failed to disconnect participant" });
    }
  }
}

export default new MeetingController();