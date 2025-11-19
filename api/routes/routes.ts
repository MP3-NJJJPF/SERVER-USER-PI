import express from 'express';
import userRoutes from './userRoutes';
import meetingRoutes from './meetingRoutes';

const router = express.Router();

router.use('/users', userRoutes);
router.use('/meetings', meetingRoutes);

export default router;