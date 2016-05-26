# TO ADD NEW LANGUAGES
# ./addLanguage.sh language_code

echo "Extracting strings"
pybabel extract -F ../src/octoprint/server/babel.cfg -o messages.pot ..
echo "Adding new language " $1
pybabel init -i messages.pot -d ../src/octoprint/translations -l $1
echo "========= COMPLETED ========="
echo "This will only create the structure, now you need to translate the strings inside translations/i18n, and then run compileTranslations.sh"
echo "============================="
