import express from "express";
import { addNew, deleteApplication, getApplicationById, getManagerApplications, getUserApplications, list, update } from "../controller/application.controllers";

const productRouter = express.Router();

productRouter.post('/add', addNew);
productRouter.get('/list', list);
productRouter.put('/update', update);
productRouter.get('/findByUser', getUserApplications);
productRouter.get('/findByManager', getManagerApplications);
productRouter.get('/findById', getApplicationById);
productRouter.delete('/delete', deleteApplication);

export default productRouter;