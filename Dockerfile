FROM ubuntu:20.04

RUN apt update -qy && apt install -qy nodejs make gcc python curl fish
RUN echo /usr/bin/fish | tee -a /etc/shells
RUN chsh -s /usr/bin/fish
ENV SHELL=fish
RUN curl -fsSL https://get.pnpm.io/install.sh | sh -
WORKDIR /app
CMD /usr/bin/fish
