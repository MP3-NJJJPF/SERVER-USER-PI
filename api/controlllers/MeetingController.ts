import { Request, Response } from "express";
import { nanoid } from "nanoid";

export class MeetingController {

  /**
   * Creates a new meeting with a unique formatted ID.
   * Example output: "A1b-2C3-d4E"
   *
   * @param req Express Request object
   * @param res Express Response object
   */
  async createMeeting(req: Request, res: Response): Promise<void> {
    try {
      // Generate a random 9-character ID using nanoid.
      // Example: "A1b2C3d4E"
      const rawId = nanoid(9);

      // Split the ID into groups of 3 and join them with hyphens.
      // Regex: .{1,3} matches every 1–3 characters.
      // Example: ["A1b", "2C3", "d4E"] → "A1b-2C3-d4E"
      const formattedId = rawId.match(/.{1,3}/g)?.join("-") || rawId;

      // Log the creation event with a timestamp.
      console.log(`Meeting created: ${formattedId} at ${new Date().toISOString()}`);

      // Respond to the client with the created meeting ID.
      res.status(201).json({
        ok: true,
        meetingId: formattedId,
        createdAt: new Date().toISOString(),
        message: "Meeting created successfully"
      });

    } catch (error) {
      // Log the error and return a 500 response.
      console.error("Error creating meeting:", error);
      
      res.status(500).json({
        ok: false,
        error: "An error occurred while creating the meeting"
      });
    }
  }

  /**
   * Returns provisional meeting information.
   * No database search is performed here; the ID is simply displayed.
   *
   * @param req Express Request object
   * @param res Express Response object
   */
  async getMeeting(req: Request, res: Response): Promise<void> {
    // Extract the :id parameter from the route
    const { id } = req.params;

    // Send a basic placeholder response
    res.json({
      ok: true,
      meetingId: id,
      message: "Meeting exists",
      createdAt: null   // Could be replaced with real DB data later
    });
  }
}

export default new MeetingController();