import { Request, Response, NextFunction } from "express";
import asyncWrapper from "../middlewares/AsyncWrapper";
import { Application as ApplicationModel } from "../model/application.model";
import { ValidateToken } from "../utils/password.utils";
import { ApplicationDoc, ExistingApplicationDoc } from "../dto/application.dto";
import UserModel from '../model/user.model';
import { sendEmail } from "../utils/notification.utils";

export const test = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.body);
    next();
});

export const addNew = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(401).json({ message: "Access denied" });
    };

    req.body.loanStatus = 'Pending';

    const newApplication = await ApplicationModel.create(req.body);

    if (newApplication) {
        // Automatically assign the new application to a manager
        const managers = await UserModel.find({ role: "Manager" });

        // Calculate the number of applications assigned to each manager
        const managerApplicationsCount = await Promise.all(managers.map(async (manager) => {
            const count = await ApplicationModel.countDocuments({ managerId: manager._id });
            return { managerId: manager._id, count: count };
        }));

        // Identify the manager with the fewest assigned applications
        const sortedManagers = managerApplicationsCount.sort((a, b) => a.count - b.count);
        const selectedManager = await UserModel.findById(sortedManagers[0].managerId);
        const selectedManagerId = selectedManager?._id;

        // Assign the new application to the identified manager
        await ApplicationModel.findByIdAndUpdate(newApplication._id, { managerId: selectedManagerId });

        res.status(201).json({ message: "Application added successfully", application: newApplication });
    };
});



export const list = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const applications = await ApplicationModel.find({});
    res.status(200).json({ applications });
});


export const update = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming application ID comes from the request URL

    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(401).json({ message: "Access denied" });
    }
    
    const existingLoanDetails = await ApplicationModel.findById(id);
    
    if (existingLoanDetails?.loanStatus !== req.body.loanStatus && req.body.loanStatus === 'Approved') {
        const updatedLoan = await ApplicationModel.updateOne({ _id: id }, req.body);
        if (updatedLoan) {
            await sendEmail(req.body.email, "Loan Approved", `Your loan application has been approved`);
            res.status(200).json({ message: "Application updated successfully", application: updatedLoan });
        } else {
            res.status(500).json({ message: "Error updating application" });    
        }
    } else if (existingLoanDetails?.loanStatus !== req.body.loanStatus && req.body.loanStatus === 'Rejected') {
        const updatedLoan = await ApplicationModel.updateOne({ _id: id }, req.body);
        if (updatedLoan) {
            await sendEmail(req.body.email, "Loan Rejected", `Your loan application has been rejected`);
            res.status(200).json({ message: "Application updated successfully", application: updatedLoan });
        } else {
            res.status(500).json({ message: "Error updating application" });    
        }
    }
});

export const getUserApplications = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(401).json({ message: "Access denied" });
    }
    // Get user ID from the request (e.g., from req.user)
    const userId = req.user?._id;

    // Find applications where seller matches the user ID
    const userApplications = await ApplicationModel.find({ applicantId: userId })
        
    res.status(200).json({ applications: userApplications });
});

export const getManagerApplications = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(401).json({ message: "Access denied" });
    }
    // Get user ID from the request (e.g., from req.user)
    const userId = req.query.managerId;

    // Find applications where seller matches the user ID
    const userApplications = await ApplicationModel
        .find({ managerId: { $eq: userId } })
        .populate({ path: "managerId", select: "firstName lastName email" });

    res.status(200).json({ applications: userApplications });
});


export const getApplicationById = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming application ID comes from the request URL

    // Find the application by ID
    const application = await ApplicationModel
        .findById(id)
        .populate({ path: "managerId", select: "firstName lastName email"  });

    if (application) {
        res.status(200).json({ application });
    } else {
        res.status(404).json({ message: "Application not found" });
    }
});

export const deleteApplication = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token (assuming authorization is required for deletion)
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(401).json({ message: "Access denied" });
    }

    const { id } = req.query;

    // Find the application to delete
    const applicationToDelete = await ApplicationModel.findById(id);

    if (!applicationToDelete) {
        return res.status(404).json({ message: "Application not found" });
    }

    // Delete the application
    await applicationToDelete.deleteOne();

    res.status(200).json({ message: "Application deleted successfully" });
});