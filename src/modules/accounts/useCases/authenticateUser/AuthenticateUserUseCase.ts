import { compare } from "bcrypt";
import { sign } from "jsonwebtoken";
import { inject, injectable } from "tsyringe";

import { AppError } from "../../../../errors/AppError";
import { IUsersRepository } from "../../repositories/IUsersRepository";

interface IRequest {
  email: string;
  password: string;
}

interface IResponse {
  user: {
    name: string;
    email: string;
  };
  token: string;
}

@injectable()
class AuthenticateUserUseCase {
  constructor(
    @inject("UsersRepository")
    private userRepository: IUsersRepository
  ) {}

  async execute({ email, password }: IRequest): Promise<IResponse> {
    // Usuário existe?
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      throw new AppError("Email/password incorrect.");
    }

    // Senha está correta?
    const passwordMatch = await compare(password, user.password);

    if (!passwordMatch) {
      throw new AppError("Email/password incorrect.");
    }

    // Gerar JWT
    const token = sign({}, "da4e2b3acc31c0d220c5a42e52328c2c", {
      subject: user.id,
      expiresIn: "1d",
    });

    // Criando objeto de retorno
    const tokenReturn: IResponse = {
      user: {
        name: user.name,
        email: user.email,
      },
      token,
    };

    return tokenReturn;
  }
}

export { AuthenticateUserUseCase };
