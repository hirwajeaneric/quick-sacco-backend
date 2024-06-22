import express from "express";
import { addNew, deleteApplication, getApplicationById, getUserApplications, list, update } from "../controller/application.controllers";

const productRouter = express.Router();

productRouter.post('/add', addNew);
productRouter.get('/list', list);
productRouter.put('/update', update);
productRouter.put('/findByUser', getUserApplications);
productRouter.put('/findById', getApplicationById);
productRouter.put('/delete', deleteApplication);

export default productRouter;