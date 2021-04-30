import { NextFunction, Request, Response } from "express";
import { verify } from "jsonwebtoken";

import { AppError } from "../errors/AppError";
import { UsersRepository } from "../modules/accounts/repositories/implementations/UsersRepository";

interface IPayload {
  sub: string;
}

export async function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
): Promise<void> {
  // Capturar Token do Usuário (Headers)
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    throw new AppError("Token missing.", 401);
  }

  // authHeader: "Bearer InR5cCIpXVCJ9.E2MTk3MjkImV.ucUxKdlak4"
  // [0]: Bearer , [1] InR5cCIpXVCJ9.E2MTk3MjkImV.ucUxKdlak4
  const [, token] = authHeader.split(" ");

  try {
    // Desestruturando JWT pegando o "sub" e chamando de "user_id"
    const { sub: user_id } = verify(
      token,
      "da4e2b3acc31c0d220c5a42e52328c2c"
    ) as IPayload;

    const usersRepository = new UsersRepository();

    const user = usersRepository.findById(user_id);

    if (!user) {
      throw new AppError("User does not exists.", 401);
    }

    request.user = {
      id: user_id,
    };

    next();
  } catch {
    throw new AppError("Invalid token.", 401);
  }
}
