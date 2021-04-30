import { inject, injectable } from "tsyringe";

import { deleteFile } from "../../../../utils/file";
import { IUsersRepository } from "../../repositories/IUsersRepository";

interface IRequest {
  user_id: string;
  avatar_file: string;
}

@injectable()
class UpdateUserAvatarUseCase {
  constructor(
    @inject("UsersRepository")
    private usersRepository: IUsersRepository
  ) {}

  async execute({ user_id, avatar_file }: IRequest): Promise<void> {
    // Buscando usuário
    const user = await this.usersRepository.findById(user_id);

    // Caso usuário possuir avatar -> deletar o antigo
    if (user.avatar) {
      await deleteFile(`./tmp/avatar/${user.avatar}`);
    }

    // Atualizando usuário com um novo avatar
    user.avatar = avatar_file;

    // Atualizando DB
    await this.usersRepository.create(user);
  }
}

export { UpdateUserAvatarUseCase };
