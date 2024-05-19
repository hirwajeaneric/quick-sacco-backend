import express from "express";
import { addNew, list, update } from "../controller/application.controllers";
import { validateAddApplication } from "../utils/applicationValidation";

const productRouter = express.Router();

productRouter.post('/add', validateAddApplication, addNew);
productRouter.get('/list', list);
productRouter.put('/update', update);

export default productRouter;