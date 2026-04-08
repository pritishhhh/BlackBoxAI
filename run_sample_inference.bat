@echo off
echo ================================================================================
echo RUNNING SAMPLE INFERENCE FOR BOTH MODELS
echo ================================================================================
echo.

echo [1/2] Running Standard Model...
echo.
cd standard_model
python run_inference_simple.py
if %errorlevel% neq 0 (
    echo ERROR: Standard model failed!
    pause
    exit /b 1
)
cd ..

echo.
echo ================================================================================
echo.

echo [2/2] Running Proprietary Model...
echo.
cd proprietary_model
python run_inference_simple.py
if %errorlevel% neq 0 (
    echo ERROR: Proprietary model failed!
    pause
    exit /b 1
)
cd ..

echo.
echo ================================================================================
echo BOTH MODELS COMPLETED SUCCESSFULLY!
echo ================================================================================
echo.
echo Results saved to:
echo   - datasets\Standard\standard_test_dataset_results.csv
echo   - datasets\Proprietary\proprietary_data_test_results.csv
echo.
pause

