/**
 * Represents a meeting document stored in Firestore.
 * 
 * A meeting allows 2–10 participants to join using an ID.
 * Firestore stores meeting metadata while Socket.IO handles real-time features.
 */

import { Timestamp } from "firebase-admin/firestore";

/** Structure of one participant inside a meeting */
export interface IParticipant {
  uid: string;
  name: string;
  joinedAt: Timestamp | Date;
  isConnected: boolean;
}

/**
 * Main Meeting interface for Firestore documents.
 */
export interface IMeeting {
  /** Custom formatted ID, ex: "A1b-2C3-d4E" */
  meetingId: string;

  /** Optional: who created the meeting */
  hostId?: string | null;

  /** Whether the meeting is currently active */
  isActive: boolean;

  /** Max number of participants allowed (default: 10) */
  maxParticipants: number;

  /** Array of connected participants */
  participants: IParticipant[];

  /** Date the meeting was created */
  createdAt?: Timestamp;

  /** Date last update occurred */
  updatedAt?: Timestamp;
}

/**
 * Type used when creating a new meeting
 */
export type IMeetingCreate = Omit<IMeeting,
  "createdAt" | "updatedAt" | "participants"
>;

/**
 * Type used when updating meeting data
 */
export type IMeetingUpdate = Partial<IMeeting>;
