resource "aws_lambda_function" "data_aegis" {
  function_name = "data-aegis-api-tf"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_handler.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 512

  filename         = "../lambda_deploy.zip"
  source_code_hash = filebase64sha256("../lambda_deploy.zip")

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      GROQ_API_KEY = var.groq_api_key
    }
  }
}