import { db } from "../config/firebase.config";
import { CollectionReference, DocumentData } from "firebase-admin/firestore";

/**
 * Base Data Access Object (DAO) class for Firestore operations.
 * Provides generic CRUD operations that can be inherited by specific DAOs.
 * 
 * @template T - The type of document stored in the collection (must extend DocumentData)
 */
export default class GlobalDAO<T extends DocumentData> {
  /** Reference to the Firestore collection */
  protected collectionRef: CollectionReference<T>;

  /**
   * Constructor initializes the collection reference
   * @param collectionName - The name of the Firestore collection (e.g., "users", "products")
   */
  constructor(collectionName: string) {
    // Get reference to the collection and cast it to the appropriate type
    this.collectionRef = db.collection(collectionName) as CollectionReference<T>;
  }

  /**
   * Creates a new document in the collection
   * @param data - The data to store in the document
   * @returns The ID of the newly created document
   */
  async create(data: T): Promise<string> {
    // Add the document with automatic timestamp fields
    const docRef = await this.collectionRef.add({
      ...data,
      createdAt: new Date(), // Timestamp when document was created
      updatedAt: new Date(), // Timestamp when document was last updated
    } as T);
    return docRef.id; // Return the auto-generated document ID
  }

  /**
   * Retrieves a document by its ID
   * @param id - The document ID to fetch
   * @returns The document data if found, null otherwise
   */
  async getById(id: string): Promise<T | null> {
    const snap = await this.collectionRef.doc(id).get();
    // Check if document exists before returning data
    return snap.exists ? (snap.data() as T) : null;
  }

  /**
   * Updates an existing document
   * @param id - The document ID to update
   * @param data - Partial data to update (only specified fields will be updated)
   */
  async update(id: string, data: Partial<T>): Promise<void> {
    await this.collectionRef.doc(id).update({
      ...data,
      updatedAt: new Date(), // Automatically update the timestamp
    });
  }

  /**
   * Deletes a document from the collection
   * @param id - The document ID to delete
   */
  async delete(id: string): Promise<void> {
    await this.collectionRef.doc(id).delete();
  }

  /**
   * Retrieves all documents from the collection
   * @returns An array containing all documents in the collection
   */
  async getAll(): Promise<T[]> {
    const snapshot = await this.collectionRef.get();
    // Map through all documents and extract their data
    return snapshot.docs.map((doc) => doc.data() as T);
  }
}