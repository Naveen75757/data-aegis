resource "aws_lambda_function" "data_aegis" {
  function_name = "data-aegis-api-tf"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_handler.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 512

  filename         = "../lambda_deploy.zip"
  source_code_hash = filebase64sha256("../lambda_deploy.zip")

  environment {
    variables = {
      GROQ_API_KEY = var.groq_api_key
    }
  }
}