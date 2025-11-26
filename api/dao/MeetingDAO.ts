import GlobalDAO from "./GlobalDAO";
import { IMeeting } from "../models/Meetings";
import { FieldValue } from "firebase-admin/firestore";

/**
 * MeetingDAO - Handles all database operations for meetings.
 * Extends GlobalDAO to provide meeting-specific CRUD operations and participant management.
 */
class MeetingDAO extends GlobalDAO<IMeeting> {
    /**
     * Creates an instance of MeetingDAO.
     * Initializes the parent GlobalDAO with the "meetings" collection.
     */
    constructor() {
        super("meetings"); // Collection name
    }

    /**
     * Retrieves a meeting by its unique meeting ID.
     * 
     * @param {string} id - The unique meeting identifier to search for
     * @returns {Promise<IMeeting | null>} The meeting data if found, null otherwise
     * @throws {Error} Any error encountered during the database query, except "meeting-not-found"
     */
    async getMeetingById(id: string): Promise<IMeeting | null> {
        try {
            // Query Firestore collection for a document with matching meetingId
            const snapshot = await this.collectionRef
                .where("meetingId", "==", id)
                .limit(1)
                .get();

            // If no document is found, return null
            if (snapshot.empty) {
                return null;
            }

            // Extract the meeting data from the first document in the snapshot
            const data = snapshot.docs[0].data() as IMeeting;

            // Return the meeting object
            return data;
        } catch (error: any) {
            // If the error is a "meeting not found" error, return null instead of throwing
            if (error.code === "/meeting-not-found") {
                return null;
            }
            // Re-throw any other errors to be handled by the caller
            throw error;
        }
    }

    /**
     * Connects a participant to a meeting.
     * If the participant already exists, updates their connection status.
     * If the participant is new, adds them to the meeting's participant list.
     * 
     * @param {string} meetingId - The unique identifier of the meeting
     * @param {string} userId - The unique identifier of the user/participant
     * @param {string} [name] - Optional display name for the participant
     * @returns {Promise<void>}
     */
    async connectParticipant(meetingId: string, userId: string, name?: string) {
        // Query Firestore for the meeting document with the matching meetingId
        const snapshot = await this.collectionRef
            .where("meetingId", "==", meetingId)
            .limit(1)
            .get();

        // If no meeting is found, exit early
        if (snapshot.empty) return;

        // Get a reference to the meeting document
        const docRef = snapshot.docs[0].ref;
        // Extract the meeting data from the document
        const meeting = snapshot.docs[0].data() as IMeeting;

        // Get the existing participants array, or initialize as empty array if none exists
        const participants = meeting.participants || [];

        // Check if the user is already a participant in the meeting
        const existing = participants.find(p => p.uid === userId);

        if (existing) {
            // User already exists, just mark them as connected
            existing.isConnected = true;

        } else {
            // User is new, add them to the participants array with initial data
            participants.push({
                uid: userId,
                name: name ?? "",
                joinedAt: new Date(),
                isConnected: true
            });
        }

        // Update the meeting document with the modified participants list and timestamp
        await docRef.update({
            participants,
            updatedAt: new Date()
        });
    }

    /**
     * Disconnects a participant from a meeting.
     * Updates the participant's connection status to false without removing them from the meeting.
     * 
     * @param {string} meetingId - The unique identifier of the meeting
     * @param {string} userId - The unique identifier of the user/participant to disconnect
     * @returns {Promise<void>}
     */
    async disconnectParticipant(meetingId: string, userId: string) {
        // Query Firestore for the meeting document with the matching meetingId
        const snapshot = await this.collectionRef
            .where("meetingId", "==", meetingId)
            .limit(1)
            .get();

        // If no meeting is found, exit early
        if (snapshot.empty) return;

        // Get a reference to the meeting document
        const docRef = snapshot.docs[0].ref;
        // Extract the meeting data from the document
        const meeting = snapshot.docs[0].data() as IMeeting;

        // Get the existing participants array, or initialize as empty array if none exists
        const participants = meeting.participants || [];

        // Find the participant with the matching userId
        const participant = participants.find(p => p.uid === userId);

        // If the participant exists, mark them as disconnected
        if (participant) {
            participant.isConnected = false;
        }

        // Update the meeting document with the modified participants list and timestamp
        await docRef.update({
            participants,
            updatedAt: new Date()
        });
    }
}

export default new MeetingDAO();