import { ApiResponse } from "../utils/api-repsonse.js";
import { asyncHandler } from "../utils/async-handler.js";

/*
 method -1
 const heathCheck = (req, res) => {
  try {
    return res
      .status(200)
      .json(new ApiResponse(200, { message: "Server is running" }));
  } catch (error) {
    return res
      .status(500)
      .json(new ApiError(500, { message: "something went wrong" }));
  }
 }; 
*/

const healthCheck = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, { message: "Server is running" }));
});
export { healthCheck };
