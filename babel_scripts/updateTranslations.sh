# Use when new values are added on /templates/*.jinja2 or *.py
echo "Updating translations"
echo "Extracting new strings"
pybabel extract -F ../src/octoprint/server/babel.cfg -o messages.pot ..
echo "Updating translations"
pybabel update -i messages.pot -d ../src/octoprint/translations
