import crypto from "crypto";
import multer from "multer";
import { resolve } from "path";

export default {
  upload(folder: string) {
    return {
      storage: multer.diskStorage({
        destination: resolve(__dirname, "..", "..", folder),
        filename: (request, file, callback) => {
          // Criar uma hash -> jf89676whde64
          const fileHash = crypto.randomBytes(16).toString("hex");

          // Concatenar hash + filename
          const fileName = `${fileHash}-${file.originalname}`;

          return callback(null, fileName);
        },
      }),
    };
  },
};
