FROM public.ecr.aws/docker/library/python:3.13.2

LABEL maintainer="tortxof@gmail.com"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ADD . /app

WORKDIR /app

RUN uv sync --frozen

CMD ["uv", "run", "gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
