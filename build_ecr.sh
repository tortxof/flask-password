aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws/m3l3l1j4
docker build -t flask-password https://github.com/tortxof/flask-password.git
docker tag flask-password:latest public.ecr.aws/m3l3l1j4/flask-password:latest
docker push public.ecr.aws/m3l3l1j4/flask-password:latest
