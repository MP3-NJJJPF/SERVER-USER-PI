// import admin from "firebase-admin";
// import path from "path";

// // Determine the path to the Firebase service account key
// // If the environment variable GOOGLE_APPLICATION_CREDENTIALS is set,
// // use that path; otherwise, fall back to a local JSON file
// const keyPath =
//   process.env.GOOGLE_APPLICATION_CREDENTIALS ||
//   path.join(__dirname, "../../serviceAccountKey.json");

// // Load the service account credentials dynamically
// const serviceAccount = require(path.resolve(keyPath));

// // Initialize the Firebase Admin SDK using the service account credentials
// // This grants the server full administrative access to Firebase services
// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount),
// });

// // Export Firestore and Auth instances to use across the backend
// export const db = admin.firestore();
// export const auth = admin.auth();

// // Export the entire admin instance for flexibility
// export default admin;

import admin from "firebase-admin";
import path from "path";
import fs from "fs";

let serviceAccount: any;

// Check if service account credentials are provided via environment variable
if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  // Parse the credentials from the environment variable (expected as JSON string)
  serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS);
} else {
  // Fall back to reading credentials from a local file
  // Construct the path to the service account key file (two directories up from current file)
  const keyPath = path.join(__dirname, "../../serviceAccountKey.json");
  // Read the file synchronously as a UTF-8 string
  const file = fs.readFileSync(keyPath, "utf8");
  // Parse the JSON content from the file
  serviceAccount = JSON.parse(file);
}

// Initialize the Firebase Admin SDK with the service account credentials
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Export Firestore database instance for use in other modules
export const db = admin.firestore();

// Export Firebase Auth instance for use in other modules
export const auth = admin.auth();

// Export the entire admin SDK as default export
export default admin;