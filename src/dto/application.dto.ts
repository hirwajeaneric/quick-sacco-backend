export interface ApplicationDoc extends Document {
    firstName: string;   
    lastName: string;
    nationalId: string;
    email: string;
    teacherId: string;
    phone: string;
    dateOfBirth: Date;
    gender: "Male" | "Female" | "Other";
    maritalStatus: "Single" | "Married" | "Divorced" | "Widowed";
    numberOfDependencies: number;
    workSchool: string;
    position: string;
    monthlySalary: number;
    amountToPayPerMonth: number;
    amountRequested: number;
    repaymentPeriod: number;
    bankAccountNumber: string;
    proofOfEmployment: string;
    copyOfNationalId: string;
    loanStatus: "Pending" | "Update required" | "Approved" | "Rejected";
};
export interface ExistingApplicationDoc extends ApplicationDoc {
    _id: string | {};   
};