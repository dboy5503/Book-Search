import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

interface JwtPayload {
  _id: unknown;
  username: string;
  email: string,
}

export const authenticateToken = (context: { req: Request, res: Response }) => {
  const authHeader = context.req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];
    const secretKey = process.env.JWT_SECRET_KEY || '';

    return new Promise((resolve, reject) => {
      jwt.verify(token, secretKey, (err, user) => {
        if (err) {
          context.res.sendStatus(403); // Forbidden
          return reject(new Error('Forbidden'));
        }

        context.req.user = user as JwtPayload;
        resolve(user);
      });
    });
  } else {
    context.res.sendStatus(401); // Unauthorized
    throw new Error('Unauthorized');
  }
};

export const signToken = (username: string, email: string, _id: unknown) => {
  const payload = { username, email, _id };
  const secretKey = process.env.JWT_SECRET_KEY || '';

  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
};
