# learndocker
Learn docker hands on 
//build is to build image from dockerimage, run is to run container from image. 
Docker commandlines
docker image ls
docker image rm <image_id>
docker build -t <docker_image_name> . //-t for tagging the image with a specific name 
docker run -d --name node-app node-app-image //-d for detach mode from the main cli, node-app is the name of the container
docker ps -a// show docker container list with an -all flag
//Gotta stop the container before delete so use -f flag to force deletion
docker rm node-app -f
docker run -p 8080:8080 // after : is the port app should run on and before : is the port traffic should come from
//To access interactive terminal name of the container and then bash execute
docker exec -it node-app bash //exist cmd for exiting
//Bind mount Volume where -v flag stands to mount a volume to a container to store the state and make changes to the state, usecase is nodemon
docker run -v %cd%:/app //pathtofolderonlocalmachine:pathtofolderoncontainer %cd% for windows ${pwd} for powershell $(pwd)for linux and mac
docker logs node-app // to check the logs
docker run -v %cd%:/app -v /app/node_modules //will create an anonymous volume for node_modules and will simply copy all files except for node_modules which shall prevent it from overriding the empty folder.
// To avoid making write request to your source code 
docker run -v ${pwd}:/app:ro //make it read only
docker volume ls
docker volume prune // delete unnecessary volumes
// to delete both container and associated volume, you do a docker rm -vf
docker run -v ${pwd}:/app:ro -v /app/node_modules --env-file ./.env //To include env file
docker-compose up -d 
docker-compose down -v
docker compose doesnt know if there is any change in the dockerfile so you mus pass in build flag manually to rebuild the image if not already present
docker-compose up -d --build
Since the dockerignore runs in the first phase of the build process, however when volume enters the build, it stores copies over all files regardless of the files that are in the .dockerignore file
docker-compose -f docker-compose.yml -f docker-compose-dev.yml up -d // -f file should be in order first is base and later is environment
To prevent any dev dependencies to run in the server use npm install --only=production
