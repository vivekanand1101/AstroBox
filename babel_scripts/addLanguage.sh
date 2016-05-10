echo "Extracting strings"
pybabel extract -F ../src/octoprint/server/babel.cfg -o messages.pot ..
echo "Adding new language " $1
pybabel init -i messages.pot -d ../src/octoprint/translations -l $1
