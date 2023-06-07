import { Module } from "@nestjs/common";
import { CryptoUtil } from "./utils/crypto.util";

@Module({
    providers:[CryptoUtil],
    exports:[CryptoUtil]
})
export class CommonModule{}