# TO UPDATE TRANSLATIONS
# If we changed or added new values to (.jinja2, .py or .js), then we need to run this.
# After this, we'll need to translate strings on messages.po and then run compileTranslations.sh

echo "Updating translations"
echo "Extracting new strings"
pybabel extract -F ../src/octoprint/server/babel.cfg -o messages.pot ..
echo "Updating translations"
pybabel update -i messages.pot -d ../src/octoprint/translations
echo "========= COMPLETED ========="
echo "Now, you can go to your translations, translate the new values added, and then run compileTranslations.sh"
echo "============================="
